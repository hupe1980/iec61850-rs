+++
title = "iec61850-rs — IEC 61850 in Rust: GOOSE, Sampled Values, MMS client and server"
description = "Open-source IEC 61850 library for Rust. GOOSE and Sampled Values publishers and subscribers (9-2LE, IEC 61869-9), an MMS client and server over the whole OSI station-bus stack, and SCL as the configuration for both. Panic-free decoders, sans-IO cores, no_std-capable, MIT or Apache-2.0."
template = "index.html"

[extra]
# The hero's right-hand column. It lives here rather than in the template so that it is
# ordinary markdown — syntax-highlighted by the same pipeline as every other snippet, and
# reviewable as content rather than as markup.
hero_code = """
```rust
use iec61850_rs::Fc;
use iec61850_rs::client::Client;
use iec61850_rs::server::{Ied, Server};

// A server: the engineering file is the model. No code generation, no build step.
let server = Server::bind("0.0.0.0:102", Ied::from_scl_file("relay.cid", None)?)?;

// A client: six OSI layers, the ACSE association and MMS Initiate, in one call.
let mut c = Client::connect("10.0.0.5:102")?;
for ld in c.server_directory()? {              // GetServerDirectory
    println!("{ld}");
}
let w = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?;   // one round trip, typed back
```
"""

# Answers to the questions a reader arrives with, rendered on the page and as FAQPage
# structured data from this one source, so the two cannot drift apart.
[[extra.faq]]
q = "Is there an IEC 61850 library for Rust?"
a = "This is one. It implements the process bus — GOOSE and Sampled Values — and the MMS station bus on both sides: the whole OSI stack, the association state machine over it, and above that a client and a server that browse, read, write, report, control, transfer files, read logs and edit setting groups. It is tested against real substation captures and against itself over a socket. It is pre-1.0 and has not been through a conformance laboratory. libiec61850 (C, GPLv3 or commercial) is the mature alternative if you need a certified stack today and its licence suits you."

[[extra.faq]]
q = "Which parts of IEC 61850 does it cover?"
a = "GOOSE (IEC 61850-8-1), Sampled Values (IEC 61850-9-2 with the 9-2LE guideline and IEC 61869-9), the MMS station bus with its whole OSI stack — TPKT, COTP, session, presentation, ACSE — and the ACSI services above it in both directions: browse, read, write, report control blocks, all four control models, file services, logs, setting groups and type discovery. SCL (IEC 61850-6) loads an IED model, resolves what an IED subscribes to, and configures the server. Edition 2.1 semantics throughout, including the Edition 2 simulation bit and the IEC 62351-6 replay-protection state machine."

[[extra.faq]]
q = "Can I run an IEC 61850 server or IED simulator with it?"
a = "Yes, and the SCL file is the whole configuration — there is no generated model and no build step. `ied sim relay.icd` serves every IED in a file, each on its own port, with a report engine, all four control models, setting groups, a sandboxed file store and logs. In code it is `Server::bind(addr, Ied::from_scl_file(path, None)?)`, plus a hook where your application decides whether the breaker actually moves."

[[extra.faq]]
q = "Can it run on a microcontroller?"
a = "Yes. The protocol cores — including the MMS association state machine — build `no_std` (with `alloc`; every module needs an allocator and none pretends otherwise), and CI compiles them for `thumbv7em-none-eabihf` on every push. They own no socket, spawn no thread and never read a clock, so the same code runs under an async runtime, on a bare-metal timer, or in a simulation."

[[extra.faq]]
q = "How fast is it, and does it allocate?"
a = "It allocates nothing once running — a counting allocator asserts zero allocations across a thousand GOOSE retransmissions and a second of IEC 61869-9 publishing at 2400 frames per second. Timing has not been measured on reference hardware, so no latency figure is claimed."

[[extra.faq]]
q = "Does it do the IEC 62351 security extensions?"
a = "The IEC 62351-6 replay-protection state machine, yes — it is mandatory for a conforming subscriber whether or not the stream carries security, so it is always on. The layer-2 authentication extension and TLS (IEC 62351-3) are not implemented: the extension's field layout is behind the IEC paywall, and guessing it would be worse than leaving it out."

[[extra.faq]]
q = "What licence is it under, and can I use it commercially?"
a = "MIT or Apache-2.0, at your option. That is deliberate: a permissive licence is the single biggest reason a device vendor cannot use the established open-source stack."
+++

<section class="band soft">
<div class="wrap">

## Why another IEC 61850 library

IEC 61850 is how substations talk. Protection trips travel as **GOOSE** frames that must
arrive within 3 ms; instrument transformers stream **Sampled Values** at 4800 or 14 400
samples a second. Both run straight over Ethernet, with no transport layer to absorb a
mistake. Above them, **MMS** carries the data model, reports and control over six layers of
OSI that IEC 61850-8-1 inherited whole.

The mature implementations are C ([libiec61850][lib], GPLv3 or a commercial licence) and
Java ([IEC61850bean][bean], MMS only). Both are good; neither is a permissively licensed,
memory-safe core you can put in a merging unit, a WebAssembly analyser, or a bare-metal
IED. libiec61850's own changelog is the argument: stack overflows, out-of-bounds reads and
writes, double frees, integer overflows in the BER decoder — the class of defect a
bounded, fuzzed, `unsafe`-free decoder does not have.

`iec61850-rs` is that core. `#![forbid(unsafe_code)]` across the library, a `no_std` build
for microcontrollers, and MIT or Apache-2.0.

[lib]: https://github.com/mz-automation/libiec61850
[bean]: https://www.beanit.com/iec-61850/

</div>
</section>

<section class="band">
<div class="wrap">

## What makes it correct

<p class="sub">Each of these is a property the protocol demands and a plausible-looking
implementation gets wrong. Each is held in place by a test against real traffic, a
third-party dissector, or an adversarial simulation.</p>

<div class="grid">
<div class="card">
<h3>Captures re-encode exactly</h3>
<p>Every frame of a two-IED SEL GOOSE capture and all 10,161 frames of a 9-2LE sampled-value
capture are decoded, encoded again, and required to match <strong>byte for byte</strong>.
Configure the publisher as the captured merging unit was configured and it reproduces that
hardware's frames. A real MMS association is held to the same standard through all six of its
layers.</p>
</div>
<div class="card">
<h3>Both ends, tested against each other</h3>
<p>The association is one type with a <code>Role</code>, so the suite loads an SCL file into
the real server and runs the real client against it over a loopback socket — browse, report,
control, setting groups, files. That proves the two halves agree about the mapping. It does
not prove either is right, and <a href="@/docs/verification.md">Verification</a> says so.</p>
</div>
<div class="card">
<h3>Wireshark is the judge</h3>
<p>Frames the encoders emit are dissected by <code>tshark</code> on every push. A malformed
marker or an expert error fails the build — and so does a field that does not dissect back to
the value we put in, which is the half that finds things. An implementation that only agrees
with itself has proved nothing.</p>
</div>
<div class="card">
<h3>Replay protection is not optional</h3>
<p>IEC 62351-6 requires a conforming subscriber to run its replay state machine
<em>whether or not</em> the stream carries security extensions. And the rule is about
liveness, not counters: a frame is rejected while the current state is inside its
<code>timeAllowedtoLive</code> and admitted once that has elapsed — that is a restarted
publisher, not an attacker, even when it comes back on the counter it was already using.</p>
</div>
<div class="card">
<h3>The simulation bit means what Ed2 says</h3>
<p>With <code>LPHD.Sim</code> set, a device processes simulated streams <em>in preference
to</em> real ones — once a test set speaks, the real publisher is ignored. A frame whose
header S bit disagrees with its PDU flag is rejected either way.</p>
</div>
<div class="card">
<h3>Nothing grows without bound</h3>
<p>Decoders enforce depth, member and length limits <em>before</em> allocating. Event queues
and the report reassembler are bounded and count what they drop, so a 4.8 kHz stream and an
application that stops draining cannot exhaust memory. Files are served in ranges, so an open
handle costs a name rather than a hundred-megabyte record — and the store is sandboxed by
construction, not by a check a caller might forget.</p>
</div>
<div class="card">
<h3>Adversarial simulation, not just unit tests</h3>
<p>Publisher against subscriber under virtual time with loss, reordering, duplication,
replay and partition, across 512 seeds in CI. The invariants are mutation-tested: breaking
the expiry rule makes them fail.</p>
</div>
<div class="card">
<h3>Zero allocations is a measured number</h3>
<p>A counting global allocator asserts <strong>none</strong> across a thousand GOOSE
retransmissions, a thousand state changes, and a second of IEC 61869-9 publishing and
reception.</p>
</div>
</div>

</div>
</section>

<section class="band soft">
<div class="wrap">

## The engineering file is the configuration

An SCD says where every stream goes, what every data set holds and how every breaker is
controlled. Most stacks make you say it a second time — in a generated model, a `.cfg`, or a
build script. Here the file *is* the configuration, for all four roles:

```rust
let subs = iec61850_rs::scl::subscriptions(&scd, "IED2", 50)?;   // what IED2 listens to
let server = Server::bind("0.0.0.0:102", Ied::from_scl_file("relay.cid", None)?)?;
let client = Client::connect_scl(&scd, "IED1", None, None)?;     // address, selectors, AP-title
let mu     = model.sv_publisher_config("IED1LD0/LLN0.msvcb01", src, 50)?;
```

A sampled-value subscription carries the publisher's **channel layout** with it, so samples
arrive decoded — for any engineered data set, not only 9-2LE's fixed four currents and four
voltages. And because the server browses out of the same file, it cannot drift from its own
SCD.

</div>
</section>

<section class="band">
<div class="wrap">

## Sans-IO, so the hard parts are testable

Every protocol core takes inputs with the caller's notion of *now*, yields outputs, and says
when it wants to be called again. No sockets, no threads, no clock reads — and no trait to
implement.

```rust
let events = subscriber.feed(now, &frame);   // or on_frame + poll_event
subscriber.on_timeout(now);
let deadline = subscriber.next_timeout();
```

That is what lets the same code run under a tokio task, on a bare-metal timer, or inside a
deterministic simulation with no I/O at all. It is also why the GOOSE publisher can hand out
a slice of a buffer it reuses, and why the sampled-value publisher can encode a frame **once**
and then patch only the sample counter and the samples — 2400 frames a second with no
encoding and no allocation in the steady state. The clock fields a merging unit advertises
(<code>smpSynch</code>, <code>refrTm</code>, <code>gmIdentity</code>) are patched in place
too, so following a PTP grandmaster costs one memcpy rather than a re-encode.

The station bus works the same way: the server's whole service layer is a function from a
request to an answer, tested with no socket, no client and no byte on a wire.

</div>
</section>

<section class="band soft">
<div class="wrap">

## A command line that runs anywhere

`ied` works on capture files and over a socket, so most of it needs no interface, no
privileges and no Linux.

```bash
ied sim relay.icd                                    # be the IED: a server from an SCL file
ied mu stream.pcap --profile f4800s2 --frames 2000   # virtual merging unit, IEC 61869-9
ied sv monitor stream.pcap --scd bay.scd             # the real subscriber, channels named by the SCD
ied goose sniff capture.pcap                         # gocbRef, stNum/sqNum, TAL, simulation bit
ied mms sniff station.pcap                           # six OSI layers: association, services, values
ied mms browse 10.0.0.5                              # a live server: devices, data, data sets
ied mms report 10.0.0.5 --rcb IED1LD0/LLN0.urcb01 --gi   # enable a report and decode it
ied mms control 10.0.0.5 IED1LD0/CSWI1.Pos true      # operate, under any control model
ied mms get 10.0.0.5 COMTRADE/rec0001.cfg out.cfg    # pull a record off an IED
ied scl validate relay.icd                           # the engineering errors the schema permits
ied scl subs bay.scd IED2                            # every ExtRef resolved to its publisher
```

That choice is what makes the tool testable: `ied mu` generates a stream, `ied sv monitor`
reads it back, `ied sim` serves a file and `ied mms browse` browses it — all in one CI job, on
every push, with no device.

`goose sniff` and `sv monitor` are not second implementations of the protocol: they run the
library's own subscriber state machines, so what the tool says about a frame is what a
subscribing IED would decide about it — replays named where they happen, and the delta
features an intrusion-detection system wants in the summary.

</div>
</section>

<section class="band">
<div class="wrap">

## Scope

<div class="grid">
<div class="card">
<h3>Built today</h3>
<p><strong>Process bus.</strong> GOOSE and Sampled Values: codecs, publishers, subscribers,
the 9-2LE and IEC 61869-9 profiles and any other engineered data set.</p>
<p><strong>Station bus, both ends.</strong> All six OSI layers, the association for both
roles, and above it a client and a server with no async runtime and no dependency: browse,
read, write, reporting, all four control models, files, logs, setting groups, type discovery
and data-set create/delete.</p>
<p><strong>Engineering.</strong> SCL loading from ICD, CID and SCD, subscription resolution,
and the engineering checks the XML schema permits. A BER codec, the wire types, pcap, and the
<code>ied</code> command line.</p>
</div>
<div class="card">
<h3>Not built</h3>
<p>Raw-socket adapters — the process bus encodes and decodes, but something else has to put
the frames on the wire.</p>
<p>TLS (IEC 62351-3) and the IEC 62351-6 authentication extension. Routable GOOSE/SV
(IEC TR 61850-90-5). Service tracking. A durable log store. An async client.</p>
</div>
<div class="card">
<h3>Not planned</h3>
<p>The XMPP mapping of IEC 61850-8-2, Edition 1 GSSE, and a graphical SCL editor —
<a href="https://github.com/openscd/open-scd">OpenSCD</a> already is one.</p>
</div>
</div>

<p class="sub">Five runnable examples ship with the crate — a GOOSE publisher driving a
subscriber, a merging unit, an MMS client against an MMS server in one process, a server built
from an SCL file, and an SCD as the configuration. Each needs no device and no network.</p>

<p class="sub">The API is pre-1.0 and will change. Nothing here has been through a
conformance laboratory; see <a href="@/docs/verification.md">Verification</a> for exactly
what is and is not proven.</p>

</div>
</section>
