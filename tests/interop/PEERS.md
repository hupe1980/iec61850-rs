# Interop peers and disagreements

The stacks `tests/interop.rs` runs this crate against, and every place they and this crate
disagreed. A row is either **this crate's** — fixed, with the test that keeps it fixed — or
**the peer's**, with the evidence; a peer's row says how the test copes with it.

| Peer | Version | Roles | Image |
|---|---|---|---|
| libiec61850 (C) | 1.6.2.1 | client and server on the station bus; GOOSE and SV publisher and subscriber | `libiec61850/Dockerfile` |
| IEC61850bean (Java) | 1.9.0 | client and server on the station bus | `iec61850bean/Dockerfile` |
| csp0924 `iec61850-*` (Rust) | 0.4.0 | client and server on the station bus | `csp0924/Dockerfile` |

## Disagreements

| Date | Peer | Scenario | What | Whose | Evidence / test |
|---|---|---|---|---|---|
| 2026-11-09 | IEC61850bean 1.9.0 | any association, both directions | With no session selector engineered, this crate sent the Calling and Called Session Selector parameters with length 0 in the session CONNECT and ACCEPT. IEC61850bean reads a selector as a 1-, 2-, 4- or 8-octet number and refused the association (`invalid length for reading numeric value`, `AcseAssociation.extractInteger`). libiec61850 accepts it, so nothing had caught it. | **this crate** — fixed: an empty selector is left out | `an_empty_session_selector_is_left_out_rather_than_sent_empty`; `iec61850bean_client_drives_this_server`, `this_client_drives_an_iec61850bean_server` |
| 2026-11-09 | IEC61850bean 1.9.0 | this client against its server | Its server does not answer MMS `Identify` at all — no response, no reject — so a client waits out its timeout. ISO 9506 answers an unsupported service with a reject. | the peer's | `ied mms identify` against it: `transport: request timed out`; the test does not call `Identify` on it |
| 2026-11-09 | libiec61850 1.6.2.1 | its SV publisher example | `SVPublisher_create(NULL, …)` sends to `CONFIG_SV_DEFAULT_DST_ADDRESS`, which is defined as the GOOSE default `01-0C-CD-01-00-01` — outside the SV range `01-0C-CD-04-xx`. A subscriber that admits the SV range drops it. | the peer's | `src/sampled_values/sv_publisher.c`; the test joins that group with `ied sv monitor --group 01-0C-CD-01-00-01`, as a subscriber engineered from an SCD would |
| 2026-11-09 | libiec61850 1.6.2.1 | its GOOSE examples against its own model | `server_example_goose/simpleIO_direct_control_goose.cid` engineers `gcbAnalogValues` at `APPID` `1000`, which SCL writes in hex (0x1000); its publisher and subscriber examples use decimal 1000 (0x03E8). A publisher that reads the file reaches no subscriber that hard-codes the example's number. | the peer's | the test re-engineers the block at `03E8` with `ied scl edit … gse … --appid 03E8` and publishes that |
| (earlier) | libiec61850 | log control block | IEC 61850-7-2 names the buffer cursor `OldEnt`/`NewEnt`; libiec61850 publishes `OldEntr`/`NewEntr`. | the peer's | this client asks for both: `this_client_reads_a_log_out_of_a_libiec61850_server` |

## Not covered, and why

- **csp0924's server, beyond browse and read.** It builds its namespace from the SCL file but
  registers report control blocks and control objects in code rather than from the file, so a
  served file's blocks are not there to drive. `this_client_drives_a_csp0924_server` covers
  directory, read and type discovery.
- **libiec61850 built natively on macOS.** Its clients built on a Mac failed to associate with
  this crate's server; the same clients built in the container associate and pass every
  scenario, on the same Mac, against the same server. The difference is the host build, not
  the protocol, and the suite no longer depends on a native build.
