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
| Protocols | GOOSE (IEC 61850-8-1), Sampled Values (IEC 61850-9-2, 9-2LE, IEC 61869-9), MMS with its OSI stack (TPKT, COTP, session, presentation, ACSE) and a **client and server** over it: browse, read, write, reporting, control, files, logs, setting groups |
| Edition | 2.1 semantics, including the Edition 2 simulation bit |
| Security | The IEC 62351-6 replay-protection state machine, always on |
| Engineering | SCL (IEC 61850-6) schema versions 2003 through 2007B4, read-only: model loading, `Inputs/ExtRef` subscription resolution, and the engineering checks the schema does not make |
| Dependencies | one optional: `roxmltree`, for SCL. The protocol cores and the MMS client have none — the client is blocking, so it needs no async runtime |
| Targets | `std`, and `no_std` + `alloc` on `thumbv7em-none-eabihf` |
| MSRV | 1.85 (Rust 2024 edition) |
| License | MIT OR Apache-2.0 |

## Status

The process bus is built and tested. On the station bus **both halves** are: the association
state machine over all six OSI layers, and above it a complete SCADA client — browse, read,
write, report control blocks with decoded reports and reassembled segments, all four control
models with `CommandTermination` and `AddCause`, file services, logs, setting groups, type
discovery and data-set create/delete — and a complete server that does the other half of every
one of those, straight from an SCL file (`ied sim relay.icd`). What is **not** implemented is
service tracking, `ObtainFile`, TLS and the raw-socket adapters — so on the process bus the
library still encodes and decodes what something else puts on the wire.
[Verification](@/docs/verification.md) is explicit about the difference between what is tested
and what is certified: nothing here has been through a conformance laboratory.
