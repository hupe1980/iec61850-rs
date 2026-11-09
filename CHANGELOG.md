# Changelog

Notable changes to `iec61850-rs`. The format follows [Keep a Changelog], and the project uses
[Semantic Versioning] — with the pre-1.0 caveat that the API changes freely between minor
versions.

Changes that alter what goes **on the wire** are marked ⚠, because those are the ones that
matter to a device on the other end of a substation LAN rather than to a compiler.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.4.0] — unreleased

GOOSE and SV leave the capture file, the server sends what its control blocks describe and
receives files, the log survives a restart, and SCL can be edited without being reformatted.

### Added

- ⚠ **GOOSE and SV on a live interface** (feature `net`, in `cli`): `net::Link` over the new
  [`rawether`](https://crates.io/crates/rawether) crate — Linux `AF_PACKET` with a `TPACKET_V3`
  ring, macOS/FreeBSD BPF — with GOOSE/SV presets (`LinkOptions::{goose, sv, process_bus}`), a
  kernel filter on EtherType **and** destination, monotonic receive instants with the kernel or
  NIC timestamp beside them (`Received::wire_time`), launch-time send on `CLOCK_TAI`
  (`send_at`), drop counters and `net::drop_capabilities()`.
- ⚠ **The server publishes its GoCBs and MSVCBs.** Enabling `GoEna`/`SvEna` starts the block's
  publisher from the SCL file: GOOSE on change with the file's retransmission curve, SV every
  sample period. `Server::{publish_on, publish_to, set_source_mac, set_nominal_hz}`,
  `Acsi::{drain_frames, set_source_mac, publishing}`.
- ⚠ **ACSI `SetFile` (MMS `ObtainFile`)** on both sides, **off by default**:
  `Client::{set_file, set_file_path}`; a sans-IO transfer engine on the server
  (`server::Obtains`) that never blocks other associations; `SetFilePolicy`
  (`Off`/`Authenticated`/`Anyone`), `AcsiConfig::{set_file, max_obtains, obtain_timeout_ms}`;
  `FileStore::create`, `FileWriter`, `DirectoryStore::{allow_overwrite, with_limits}` with size
  and quota limits, hidden temporaries published only when complete, unsafe paths refused.
- ⚠ **Server-side ACSE password**: a server with `AssociationConfig::password` refuses an
  association without it (constant-time comparison); `Negotiated::authenticated`.
- **`RedbLog`** (feature `log-redb`, in `cli`): the server's log in a redb file that survives a
  restart — one transaction per append, owner-only files, a locked or foreign file refused.
  `server::check_log_store` is the `LogStore` contract as a reusable check.
- **`scl::Document` — edit SCL without reformatting it.** An unedited file is its input byte for
  byte; an edit changes only the bytes it is about and is refused if the result is not
  well-formed; `undo`/`redo` restore exact bytes. Typed operations keep references consistent
  (`rename_ied`, `remove_ied`, logical nodes, data sets and members, GOOSE/SV/report/log control
  blocks, `ExtRef` bind/unbind, GSE/SMV/access-point addresses, history items); `Document::edit`
  and `Document::read` give raw access.
- `AddCause::{since, for_edition}`; `Controls::set_edition`.
- CLI: `ied goose sniff --iface`, `ied sv monitor --iface`, `ied mu --iface [--launch-time]`,
  `ied goose publish`, `ied sim --iface/--freq/--log-db/--password`, `ied mms put`,
  `ied scl edit` (dry-run diff, atomic write, refuses an edit that adds a validation error unless
  `--force`, records who and why in the header history). Every subcommand answers `--help`.
- Fuzz targets `log_record`, `obtain_engine`, `scl_edit`.
- Tests: live GOOSE/SV over a veth pair on Linux (both receive paths), SetFile against
  libiec61850's `file-tool` and through the Wireshark oracle, `RedbLog` against `MemoryLog` by
  proptest and across a killed process, every OpenSCD file round-tripping byte for byte.

### Changed

- ⚠ An Edition 1 server sends only Edition 1 `AddCause` values (0–18): `ObjectAlreadySelected`
  as `SelectFailed`, any other newer cause as `Unknown` — in `LastApplError` and the control
  tracker alike.
- ⚠ Enabling a GoCB/MSVCB the server cannot publish (no address, no fixed SV layout, a unicast
  USVCB) is refused with `object-value-invalid`; deleting a data set a publishing block uses is
  refused.
- ⚠ The client answers every confirmed request a server sends it instead of ignoring it.
- ⚠ A `FileRead` response is bounded by the negotiated PDU and the TSDU limit, not by
  `Limits::max_primitive_len`.
- ⚠ A log query the store cannot answer is refused with `resource` / `mass-storage-unavailable`.
- `DirectoryStore` never lists, reads or deletes a dot-file.
- `MemoryLog` evicts in O(1).
- `Error::Service` names its class ("definition (class 2)").
- `scripts/fetch-specs.sh` is now `scripts/fetch-references.sh`, writing to
  `$IEC61850_REFERENCE`; it also fetches `SCL_BaseSimpleTypes.xsd`.
- Releases publish through crates.io Trusted Publishing.

### Fixed

- ⚠ `ServiceError` answers used the wrong `errorClass` tags: `definition` is 2 and `service` 4
  (they went out as 4 and 5); `resource` (3) and `file` (11) added.
- ⚠ A deeply nested SCL file overflowed the loader's stack; `roxmltree` ≥ 0.21.2 parses
  iteratively, and a 200 000-level document is tested.
- `ied mu --help` wrote a capture called `--help`; no option is taken for a file name.

### Breaking

- MSRV is **1.90**.
- Every `LogStore` method is fallible (`Result<_, LogError>`); `by_time`/`after_entry` return
  `LogPage`; `purge` and `bounds` are required; `Logs::set_store` takes the `Ied`.
- `Negotiated`, `ServiceError` and `AcsiConfig` gain fields; `FileStore` gains `create`.

## [0.3.0] — 2026-09-06

### Added

- ⚠ **Arrays.** SCL `count` (a number or the name of a sibling attribute) builds an MMS
  `array`; `GetVariableAccessAttributes` answers `array[n] of …`; references such as
  `phsAHar(2).cVal.mag.f` carry an ISO 9506 `AlternateAccess` selection on both client and
  server (`proto::mms::alternate`); a data set may name one element via `FCDA/@ix`. New:
  `ObjectReference::selection`, `common::{Selector, split_index}`,
  `VariableSpecification::Element`, `VarKind::Array`, `Variable::at`,
  `IedModel::fcda_resolves`, `scl::MAX_ARRAY`,
  `DiagnosticCode::{UnresolvedArrayCount, ArrayTooLarge}`.
- ⚠ **Service tracking** (IEC 61850-7-2 §14): all ten classes, filled from the services the
  server answers, found by `cdc` with ordinals from the file's `EnumType`, carried by an
  ordinary report control block. One `CTS` per kind of controlled object, chosen by the
  `ctlVal` type; `OTS` records `QueryLogByTime` and `QueryLogAfter`. New:
  `common::{ServiceType, ServiceError, TrackingCdc, Tracked}`, `server::Tracking`,
  `Ied::enum_ordinal`, `Acsi::tracking`.
- ⚠ **Server-side report segmentation**: a report larger than the negotiated PDU is split
  across `InformationReport`s with `SubSeqNum` and `MoreSegmentsFollow`
  (`Engine::set_max_pdu`, `Acsi::set_association_max_pdu`).
- ⚠ **MMS `Status`, `GetCapabilityList` and `Cancel`** on both sides: `Client::status`,
  `Client::is_alive`, `Client::capabilities`, `ServerStatus`,
  `AcsiConfig::{vmd_logical_status, vmd_physical_status, capabilities}`,
  `Association::cancel`, `AssociationEvent::{Cancelled, CancelRefused}`; `ied mms status`.
- **Client reconnection** with `Backoff`, `Client::connect_retrying` and `Client::reconnect`.
  Nothing is restored implicitly; resume a buffered block with `RcbSettings::resume_after`.
- ⚠ **GOOSE and SV control blocks served** with their `DstAddress` (`PhyComAddr`) from the
  file; a unicast SV stream is a `USVCB` under `US`.
- **`LGOS`/`LSVS` supervision**: `SubscriptionStatus::from_goose`/`from_sv` and
  `Txn::supervise` publish a subscriber's state into the logical node the file declares
  (`IedModel::supervision`, `examples/supervised_subscriber.rs`).
- **`LogStore` trait** with `MemoryLog` as the default and `Server::set_log_store`.
- **Write policy**: `Fc::is_client_writable`, `server::writable_block_attribute`; `Owner`
  carries the holder's address; `Beh`/`Mod` gate controls (`AddCause::BlockedByMode`).
- `LogEntry::reason` (and `ied mms log` prints it); `BType::{Octet6, Octet16, LogOptFlds}`.
- SCL findings: `DuplicateTypeMember`, `IndexedReportControl`, `MissingLog`, `ReportTriggers`.
- `ObjectReference::to_mms_under`, `Mms::peek_invoke_id`, `EntryTime::MAX`,
  `Limits::max_list_items`, `Ied::read_reference`, `ServedDataSet::{references, len, is_empty}`,
  `DataSetMember`, `common::data_access_reason`.
- Feature badges in the API documentation (`--cfg docsrs`).
- Tests: interop against libiec61850 in both roles (`tests/interop.rs`, CI job `interop`);
  a Wireshark oracle for the whole MMS association, including segmented reports
  (`tests/tshark_mms.rs`).

### Changed

- ⚠ A report is granular in data-set **members**: a member naming a data object is one
  inclusion bit, one value and one reason code, carried as a structure.
- ⚠ A setting-group setting is served under both `SG` and `SE`; `ResvTms` expires an edit
  reservation; `CnfEdit` returns to false after an edit.
- ⚠ `SqNum` is zeroed when a report control block is enabled; `ConfRev` changes with `DatSet`;
  a `DatSet` naming an unknown data set is refused.
- ⚠ `IntgPd` reports only when `TrgOps.integrity` is set.
- `RptEna`, `GI`, `PurgeBuf` and `Resv` are cleared when the owning association ends; a
  `ResvTms` reservation outlives it by the seconds it names.
- A client whose outbound queue fills (`ServerConfig::outbound_queue`, 256 PDUs) is
  disconnected.
- `GetNameList` pages and reports are sized by the association's negotiated PDU.
- ⚠ A client may not write `ST`, `MX` or control-block counters; `EntryID` stays writable.
- `Control::execute` reads `ctlModel` from the server unless a model is stated.
- `QueryLogByTime` without an end time sends `EntryTime::MAX`.
- `read_lcb` accepts `OldEntr`/`NewEntr` as well as `OldEnt`/`NewEnt`.
- `Client::write_many` requires a functional constraint per reference; `ied mms write`
  requires `--fc`.
- `Logs` is built on `LogStore`; `DEFAULT_LOG_CAPACITY` is the default store's capacity.

### Fixed

- ⚠ A `Read` of one array element was answered with the whole array; unservable selections
  are now refused (`object-non-existent`, `object-access-unsupported`).
- ⚠ `floating-point` in a `TypeSpecification` used context tags instead of universal INTEGERs,
  breaking `GetVariableAccessAttributes` against other stacks (the old form still decodes).
- ⚠ `AARE` lacked the mandatory `result-source-diagnostic`; `JournalEntry` lacked
  `originatingApplication`; `FileDirectory`'s `listOfDirectoryEntry` was implicitly tagged.
- Data-set members naming array elements did not resolve; `ObjectReference` accepted `(`/`)`
  as name characters.
- A `GetNameList` page was capped at the data-set member limit (512).
- A response that failed to decode left its invoke id outstanding until timeout.
- The tracking mirror missed `GI`.
- `ServiceError::from_data_access` used wrong ISO 9506 codes.
- `GI`/`PurgeBuf` on a block not enabled by the caller produced orphan reports.
- A `BR` buffer was a queue drained on enable; it is now a ring, and a lost `EntryID` raises
  `BufOvfl`.
- A data-set member with no value was reported as `false`; it is now excluded.
- `LogControl/@reasonCode` was ignored.
- An `ExtRef` naming a data object did not match a data set of its attributes.
- Selecting a setting group marked it changed.

### Breaking

- `VariableSpecification` has a third variant and is no longer `Copy`; `DataAttribute`,
  `DataObject` and `Fcda` gained a field; `VarKind` gained a variant.
- `AssociationEvent::Malformed(Error)` is `Malformed { invoke_id, error }`.
- The default control model is no longer `ControlModel::DirectNormal`.
- `ServedDataSet::members` is `Vec<DataSetMember>`; `ServedDataSet::leaves` is removed.
- `Engine::on_write` and `Acsi::on_association_closed` changed signature; `Engine::commit`
  may return several `Outgoing`.

## [0.2.0] — 2026-09-06

### Added

- **Server-side time-activated operate.** An `Oper` with a future `operTm` arms the command;
  `Cancel` or a lost association disarms it, and the `ControlHook` is asked when it fires.
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

- ⚠ **Sampled-value integers could go negative on the wire** (e.g. `smpSynch = 200` encoded
  as `C8`, −56). `smpSynch`, `smpCnt`, `confRev` and `smpRate` now widen by one octet when the
  value would otherwise read as negative.
- **Server timestamps** (`TimeOfEntry`, log times, `LActTm`, `t`) came from the monotonic
  clock, so they read 1970/1984 and `QueryLogByTime` matched nothing.
- **Publishing a report could discard uncommitted application writes** from the report and
  the log.
- ⚠ **Reports used the wrong variable name**; IEC 61850-8-1 maps every report onto `RPT`.
- **A rejected request hung until its timeout** instead of returning the reject reason.
- ⚠ **The outstanding-call budget did not negotiate**; both ends now use the minimum.
- ⚠ **A COTP disconnect request carried a hard-coded reference** instead of the peer's.
- **The report assembler did not bound one run's size** and let a broken run restart
  mid-report; a run now starts at `SubSeqNum` 0.
- **`FileOpen` allocated the whole file per handle.**
- **`invokeID` and `originalInvokeID` are enforced as `Unsigned32`**; a negative one made the
  server's answer unencodable.
- **A `reject-PDU` did not round-trip** (reason read from a constructed `[0]`).
- Two `RejectReason` tables named the wrong codes: `conclude-response` 1 is `invalid-result`
  and `conclude-error` 1 is `invalid-serviceError`.
- `ied sim` and `Ied::new` no longer publish Edition 2 attributes for an Edition 1 file.

### Internal

- `tests/allocation.rs` counts **octets** as well as allocations, and its counters are
  thread-local so tests in that file may run in parallel.
- Two fuzz crashes are committed as named regression inputs under `fuzz/regressions/`.
- The fuzz smoke job discovers targets with `cargo fuzz list`.
- The `sv_publisher` target drives `smpSynch` from the fuzzer's bytes, covering both sides of
  the width boundary and the template re-encode that crossing it triggers.

## [0.1.0] — 2026-09-06

First release. GOOSE and Sampled Values with sans-IO publishers and subscribers, the OSI stack
and MMS PDUs, the association state machine in both roles, a blocking MMS client and server,
SCL loading and validation, pcap tooling and the `ied` command line.

[Unreleased]: https://github.com/hupe1980/iec61850-rs/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/hupe1980/iec61850-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/hupe1980/iec61850-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hupe1980/iec61850-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/iec61850-rs/releases/tag/v0.1.0
