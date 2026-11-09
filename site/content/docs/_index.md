+++
title = "Documentation"
description = "Guide to iec61850-rs: publish and subscribe to GOOSE and Sampled Values, run an MMS client or server on the station bus, load an IED model from SCL, and drive it all from the ied command line."
sort_by = "weight"
template = "section.html"
page_template = "page.html"
+++

`iec61850-rs` is a Rust library and command line for **IEC 61850**: the **GOOSE** messages
that carry protection signals between IEDs, the **Sampled Values** that carry
instrument-transformer measurements to them, and the **MMS** station bus above both.

These pages are the guide. The per-item API reference lives on
[docs.rs](https://docs.rs/iec61850-rs).

## Where to start

| If you want to | Read |
|---|---|
| Install it, decode a frame, run an example | [Getting started](@/docs/getting-started.md) |
| Understand GOOSE, SV, APPIDs and the process bus | [How GOOSE and Sampled Values work](@/docs/protocols.md) |
| Publish or subscribe to protection signals | [GOOSE](@/docs/goose.md) |
| Build a merging unit, or consume one | [Sampled Values](@/docs/sampled-values.md) |
| Browse, read, report and control over the station bus | [MMS](@/docs/mms.md) |
| Serve a model from an SCL file — be the IED | [Server](@/docs/server.md) |
| Configure any of it from an ICD or SCD file | [SCL and the IED model](@/docs/scl.md) |
| Do all of that from a shell | [Command line](@/docs/cli.md) |
| Know what is actually proven, and what is not | [Verification](@/docs/verification.md) |

## At a glance

| | |
|---|---|
| Protocols | GOOSE (IEC 61850-8-1), Sampled Values (IEC 61850-9-2, 9-2LE, IEC 61869-9), MMS with its OSI stack (TPKT, COTP, session, presentation, ACSE) and a **client and server** over it: browse, read, write, reporting, control, files, logs, setting groups, LGOS/LSVS supervision |
| Edition | 2.1 semantics, including the Edition 2 simulation bit |
| Security | The IEC 62351-6 replay-protection state machine, always on |
| Engineering | SCL (IEC 61850-6) schema versions 2003 through 2007B4: model loading, `Inputs/ExtRef` subscription resolution, the engineering checks the schema does not make, and editing that leaves untouched bytes untouched |
| Dependencies | all optional, per feature: `roxmltree` (SCL), `redb` (durable log), `rawether` (live interfaces). The protocol cores have none; client and server are blocking and need no async runtime |
| Targets | `std`, and `no_std` + `alloc` on `thumbv7em-none-eabihf` |
| MSRV | 1.90 (Rust 2024 edition) |
| License | MIT OR Apache-2.0 |

## Status

The process bus — over capture files and live interfaces — and both halves of the station bus —
the association over all six OSI layers, a SCADA client and a server built from an SCL file
(`ied sim relay.icd`) that also publishes its GOOSE and SV — are implemented and tested, the
station bus against **libiec61850 in both roles** in CI.

Not included: TLS (IEC 62351-3), the IEC 62351-6 authentication extension and routable GOOSE/SV. Nothing here has been through
a conformance laboratory; [Verification](@/docs/verification.md) says what is and is not
proven.
