# Changelog

Notable changes to `iec61850-rs`. The format follows [Keep a Changelog], and the project uses
[Semantic Versioning] — with the pre-1.0 caveat that the API changes freely between minor
versions.

Changes that alter what goes **on the wire** are marked ⚠, because those are the ones that
matter to a device on the other end of a substation LAN rather than to a compiler.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.2.0] — 2026-09-06

Two audit passes over the whole crate. Every entry under *Fixed* is a defect that a green test
suite did not catch, and most were found by reading the primary standard or a reference
implementation rather than by running anything.

### Added

- **Server-side time-activated operate.** An `Oper` whose `operTm` is in the future arms the
  command instead of running it; `Cancel` or a lost association disarms it, and the
  `ControlHook` is asked again when it fires rather than when it was accepted.
- **Edition-aware server.** The edition comes from the SCL file's own schema version
  (`Edition::from_scl_version`, `IedModel::edition`) and decides the report control block's
  attribute set — an Edition 1 block has no `ResvTms` and no `Owner`. `Ied::with_edition` and
  `ied sim --edition` override it; `ied sim` prints the edition it chose.
- **A pluggable wall clock on the server** (`Clock`, `SystemClock`, `Server::set_clock`,
  `Acsi::set_clock`), and `common::Now`, which carries the monotonic and absolute readings
  together so a signature cannot let one stand in for the other.
- **A typed MMS `reject-PDU`** (`proto::mms::reject`): `Reject`, `RejectReason` with the
  per-PDU-type reason tables of ISO 9506-2, and `Error::Rejected`.
- ⚠ **`Extended User Data` on a session CONNECT**, so an AARQ may reach 10 240 octets
  (X.225 §7.1.1 e), §8.3.1.21). It is a CONNECT-only parameter; an ACCEPT above 512 octets is
  still an error.
- `Ied::set_internal`, for writes the server makes while publishing.
- `Controls::next_timeout`, and `Acsi::next_timeout` now includes it.
- `ReportAssembler::with_max_entries` and `AssemblerStats::oversized`.
- `AssociationStats::rejected`.

### Changed

- ⚠ **`FileStore` reads ranges.** `read` is replaced by `info` + `read_at(path, offset, len)`,
  so a `FileOpen` costs a path and two integers rather than the whole file.
- **`Answer::UNSUPPORTED` is a reject**, not a service error, and a PDU that is not a confirmed
  request is answered with `Answer::INVALID_PDU`.
- `Publisher::set_smp_synch` (sampled values) returns `Result`: crossing the one-octet boundary
  re-encodes the frame template.
- `Initiate::request` takes the outstanding-call budget as an argument.
- `AsduOffsets` carries a `Field { at, len }` per patchable field rather than a bare offset.
- `Clock` requires `Debug`, as `FileStore` already did.
- `Engine`, `Logs`, `SettingGroups` and `Controls` take the wall-clock reading as a value.
- The `server` feature is on by default and documented as built.

### Fixed

- ⚠ **Sampled-value integers went negative on the wire.** `smpSynch`, `smpCnt`, `confRev` and
  `smpRate` were written at the widths a vendor capture happens to show, but a BER INTEGER is
  signed: `smpSynch = 200` — a local-area clock identity, IEC 61850-9-2 Ed2 allows 5–254 — went
  out as the single octet `C8`, which `tshark` reads as **−56**. The same hole sat under
  `smpCnt` on the 96 kHz profile IEC 61869-9 allows, where 65 535 in two octets is −1. Fields
  now widen by one octet only when a value would otherwise be negative, so every ordinary value
  stays byte-identical to the capture.
- **Every absolute timestamp the server published was 1984 or 1970.** A report's
  `TimeOfEntry`, a log entry's time, an `SGCB`'s `LActTm` and an operated object's `t` were all
  derived from the *monotonic* instant the state machines are driven by. `QueryLogByTime`
  therefore matched nothing.
- **Publishing a report discarded uncommitted application writes.** The report engine cleared
  the whole dirty set after writing its own counters; with more than one association that is a
  race, and the write was lost from the report *and* from the log.
- ⚠ **Reports were reported under the wrong name.** The `variableAccessSpecification` was built
  by splitting `RptID` on `/`. IEC 61850-8-1 maps every report onto the VMD-specific name
  `RPT`, which is also what libiec61850 writes.
- **A rejected request hung until its timeout.** A `reject-PDU` was handed up as an unsolicited
  PDU, so the invoke identifier stayed outstanding and the caller waited out its full request
  timeout before reporting silence instead of the reason.
- ⚠ **The outstanding-call budget did not negotiate.** The proposal was a hard-coded ten
  regardless of `max_outstanding`, and the server answered with its own configuration rather
  than the minimum, so the two ends enforced different numbers.
- ⚠ **A COTP disconnect request carried a hard-coded reference** instead of the peer's.
- **The report assembler was unbounded in one dimension.** It limited how many segment runs
  were in flight but not the size of one, and it let the segment that *broke* a run start a
  fresh one — producing a report missing its first members with nothing able to tell. A run now
  starts at `SubSeqNum` 0 or not at all.
- **`FileOpen` allocated the whole file per handle**, so server memory was
  `handles × associations × file size`, remotely chosen, on the service that moves COMTRADE
  records.
- **`invokeID` and `originalInvokeID` are `Unsigned32`** and are now enforced as such. A
  negative one made the server's own answer unencodable, which is worse than any error
  response. Found by `cargo fuzz`.
- **A `reject-PDU` reason was read from a constructed `[0]`** — the `originalInvokeID` tag — and
  re-encoded as a primitive one, giving a PDU that decodes once and not twice. Found by
  `cargo fuzz`.
- Two `RejectReason` tables named the wrong codes: `conclude-response` 1 is `invalid-result`
  and `conclude-error` 1 is `invalid-serviceError`.
- `ied sim` and `Ied::new` no longer publish Edition 2 attributes for an Edition 1 file.

### Internal

- `tests/allocation.rs` counts **octets** as well as allocations, and its counters are
  thread-local so tests in that file may run in parallel.
- Two fuzz crashes are committed as named regression inputs under `fuzz/regressions/`.
- `concepts/QUALITY.md` section numbering repaired (it had two `§5.2`s).

## [0.1.0] — 2026-09-06

First release. GOOSE and Sampled Values with sans-IO publishers and subscribers, the OSI stack
and MMS PDUs, the association state machine in both roles, a blocking MMS client and server,
SCL loading and validation, pcap tooling and the `ied` command line.

[Unreleased]: https://github.com/hupe1980/iec61850-rs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hupe1980/iec61850-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/iec61850-rs/releases/tag/v0.1.0
