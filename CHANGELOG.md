# Changelog

Notable changes to `iec61850-rs`. The format follows [Keep a Changelog], and the project uses
[Semantic Versioning] — with the pre-1.0 caveat that the API changes freely between minor
versions.

Changes that alter what goes **on the wire** are marked ⚠, because those are the ones that
matter to a device on the other end of a substation LAN rather than to a compiler.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html

## [Unreleased]

## [0.3.0] — 2026-09-06

Five audit passes. The eleventh found the same lesson as the tenth, one layer over: a **fixture
written to make the code pass is not evidence about the code**, and the way to tell is to check
the fixture against something that did not come from this repository — here, the SCL schema. The
twelfth built the last differentiator that had nothing behind it, and found that three of the
four things it looked to need from behind the IEC paywall were in the engineering file all along.
The thirteenth took the argument to its conclusion and pointed a **second stack** at both halves
of this one: six defects, none of which any oracle in this repository could have found, because
a dissector reads octets and a peer reads a *sequence*. The fourteenth followed that second
stack into the one shape this one had no model for at all — an **array** — and found the
worst-shaped defect of the lot: a request for the third harmonic answered with all sixteen,
successfully.

### Fourteenth pass — arrays, and the selection beside the name

#### Added

- ⚠ **Arrays, end to end** (D53). SCL's `count` on a `DA`, `BDA` or `SDO` builds one — a number
  or the *name* of a sibling that holds one, which is the union the schema declares ✅. The
  model carries it (`DataAttribute::count`, `DataObject::count`), the server's tree publishes it
  as an MMS `array [1]` with its length in the type, the value store keys every element by the
  index the IEC 61850 reference syntax spells, and `GetVariableAccessAttributes` answers
  `array[16] of …` where it used to answer with one element's shape.
- ⚠ **`AlternateAccess`** (`proto::mms::alternate`), on both halves. An array is where the MMS
  namespace stops, so `MHAI1.HA.phsAHar(2).cVal.mag.f` is the named variable
  `MHAI1$MX$HA$phsAHar` plus a selection carried beside it. The **reference is the whole API**:
  `Client::read`, `read_many`, `read_many_results` and `write` build the selection from the
  reference, and the server folds it back into the item path — one representation for the tree,
  the value store, the leaf walk and a report member.
- ⚠ **`FCDA/@ix`** ✅ (`tFCDA`, `SCL_IED.xsd`): a data set may name **one element** of an array.
  The index says which element and never which component is the array — only the type does — so
  it is placed by walking the model, and a file that also writes it into `daName` (which
  libiec61850's tool does 🌐) means the same member.
- `ObjectReference::selection`, `common::Selector`, `common::split_index`,
  `VariableSpecification::Element`, `server::tree::VarKind::Array`, `Variable::at`,
  `IedModel::fcda_resolves`, `scl::MAX_ARRAY`, `DiagnosticCode::{UnresolvedArrayCount,
  ArrayTooLarge}`, `DATA_ACCESS_UNSUPPORTED`, and `tests/fixtures/array.icd`. The server fuzz
  target's model gained an array, so an out-of-range index is reached by a fuzzer and not only
  by a unit test.

#### Fixed

- ⚠ **A `Read` naming one array element was answered with the whole array.** The
  `alternateAccess` beside the name was decoded and then dropped, so the server answered
  *successfully* with sixteen values where one was asked for — no error, and nothing on the wire
  to say the question had changed. A decoder that reads a field and then ignores it is worse
  than one that does not read it at all.
- **A selection the server cannot serve is now refused.** An index past the end of an array or
  on something that is not one is `object-non-existent`; an `alternateAccess` naming a *range*
  or *all* elements is `object-access-unsupported`. Each used to be a nearby answer.
- **A data-set member naming an array element did not resolve**, so `ied scl validate` reported
  every one of them as an error — on libiec61850's own harmonics model among others. The
  validator now checks the **whole** member rather than only its leaf half, and says *why*: a
  misspelt name and an index past the end of its array are different problems.
- **`ObjectReference` accepted `(` and `)` as ordinary name characters**, so `phsAHar(2)`
  parsed as a component literally called `phsAHar(2)` and every service built a name no server
  has. An index is now parsed as one, and a stray parenthesis is a reference error.
- **A `count` the schema allows is not a `count` a server can expand.** `xs:unsignedInt` goes to
  four thousand million and each element becomes its own set of values at load, so the file
  decided how much memory the process took. `scl::MAX_ARRAY` is the ceiling; above it the
  attribute is diagnosed and loaded as the scalar it will be served as.

**Breaking:** `VariableSpecification` has a third variant and is no longer `Copy`;
`DataAttribute`, `DataObject` and `Fcda` have a new field each; `VarKind` has a new variant.

### Thirteenth pass — interop against libiec61850

#### Added

- **`tests/interop.rs` and an `interop` CI job** (D52). libiec61850's client drives this server
  — `mms_utility` for browse, read and type discovery; `client_example_control` for all four
  control models and their terminations; `client_example1` for reporting with `GI` and
  `IntgPd` — and this client drives its `server_example_basic_io` and `server_example_logging`
  through the same list plus the log services. The models served are **libiec61850's own**,
  read out of its tree rather than vendored: they are under a different licence, and they are
  engineering documents this project did not write. Point `IEC61850_LIBIEC61850` at a built
  checkout; `IEC61850_REQUIRE_INTEROP=1` turns a skip into a failure, which is what CI sets.
- ⚠ **`OTS` — tracking of the two log queries.** The last tracking class with nothing behind
  it. `QueryLogByTime` and `QueryLogAfter` are recorded against the `OTS` object the file
  declares, with the query's own range as the specific half. `GetLogStatusValues` is
  deliberately not tracked: IEC 61850-8-1 maps it onto an ordinary read of the log control
  block, so nothing on the wire tells it from any other read of that block.
- ⚠ **One `CTS` tracker per kind of controlled object.** IEC 61850-7-4's `LTRK` carries
  `SpcTrk`, `DpcTrk`, `IncTrk`, `BscTrk` … 🌐, so a logical device may hold several; which one
  records a command is decided by the `bType` of its `ctlVal`, from the file on both sides. A
  double-point command no longer lands in the single-point tracker.
- `ObjectReference::to_mms_under`, `Mms::peek_invoke_id`, `EntryTime::MAX`, and
  `Limits::max_list_items`.

#### Fixed

- ⚠ **`floating-point [7]` in a `TypeSpecification` was encoded with context tags.** ISO 9506-2
  leaves `format-width` and `exponent-width` unnamed, so they are universal INTEGERs.
  `GetVariableAccessAttributes` therefore failed **in both directions** against any other
  stack, and as a timeout rather than an error. Nothing here could have caught it: Wireshark's
  MMS module has no `floating-point` in `TypeSpecification` at all, so the oracle dissected the
  wrong encoding without complaint while both halves of this crate agreed on it. The decoder
  still accepts the old form.
- **A `GetNameList` page was held to the data-set member limit** (`max_dataset_members`, 512),
  so a real device's namespace — 643 names in libiec61850's own test model — was refused as
  malformed. Listing services now use `Limits::max_list_items`; the real bound is the
  reassembled TSDU a layer below.
- **A response that did not decode left its invoke identifier outstanding**, so the line above
  surfaced as "the server did not reply" about a server that had. `AssociationEvent::Malformed`
  now carries the `invoke_id` it ends, the association releases the slot, and the caller fails
  at once with the decode error. This is D46's rule applied to the third PDU that ends a call
  without answering it. **Breaking:** `Malformed(Error)` is now
  `Malformed { invoke_id, error }`.
- ⚠ **The client never asked what `ctlModel` was.** Every select-before-operate object was
  driven as a direct control and refused with `AddCause::ObjectNotSelected`, which reads
  exactly like a broken object. `Control::execute` now reads `CF$…$ctlModel` off the server
  when the caller has not stated a model, and `ied mms control` no longer needs `--model`.
  **Breaking:** the default is no longer `ControlModel::DirectNormal`; state it to keep the
  round trip away.
- **`ObjectReference::to_mms` kept the reference's own functional constraint** where the lookup
  above needs it replaced: `CO$Pos` is the controllable object and `CF$Pos$ctlModel` is how it
  was engineered. `to_mms_under` is the deliberate replacement; `to_mms` is unchanged.
- ⚠ **`QueryLogByTime` was sent with no upper bound** when the caller gave none. That is legal
  ISO 9506 and is answered with `invalid-argument` before the server looks at the log, because
  the ACSI service is a *range*. An unstated bound is now sent as `EntryTime::MAX`.
- **`read_lcb` could not find the log's buffer cursor on half the devices in the field.** IEC
  61850-7-2 names it `OldEnt`/`NewEnt` and libiec61850 publishes `OldEntr`/`NewEntr` 🌐; the
  client now asks for both, so `Lcb::oldest` — which is the resume point — is answered either
  way. The server keeps the standard's names.
- **The tracking mirror missed `gi`.** Every tracking attribute is the control block's with a
  lower-case first letter, and a report control block's general interrogation is `GI` with
  *two* capitals, so `upper_first` alone looked for a `Gi` no model has and left the busiest
  field of every buffered tracker empty. The rule now falls back to the shouted form, which is
  consulted only when the first spelling names nothing.

### Twelfth pass

#### Added

- ⚠ **Service tracking** (IEC 61850-7-2 §14, §15.3.2, §20.6.2 — D51). A report says what
  happened in the *process*; tracking says what happened on the *wire*, which no report can:
  who enabled that control block, which client was refused and with what, whether the breaker
  that did not move was refused by the interlocking or never asked. `common::{ServiceType,
  ServiceError, TrackingCdc, Tracked}` and `server::Tracking`, wired into every write, every
  select, data-set create and delete, and the two things the server does on its own — a block
  released with its association and a reservation that ran out, which §15.3.2.2.2 names
  `InternalChange`.

  It needed no paywalled table, and that is the design: the file declares a tracking object by
  its **`cdc`** (so no name table from IEC 61850-7-4), its **`EnumType`** numbers `serviceType`
  and `errorCode` (so no ordinal table from IEC 61850-8-1, with the standard's list order as a
  labelled fallback), and every tracking class's specific half is the control block's own
  attributes with a **lower-case first letter** — so one `upper_first` replaces nine attribute
  tables. `CTS` is the exception that proves it: a control's parameters are components of the
  `Oper` the client sent, not attributes the server holds. `OTS`, the tracking of the two log
  queries, is the one class not yet filled.
- `Ied::enum_ordinal`, `Acsi::tracking`, `Engine::take_released`, `Controls::take_last_cause`,
  and `tests/fixtures/tracking.icd`. The server fuzz target's model gained the tracking objects
  too, so the mirror path is fuzzed rather than only tested — and lost the duplicate `setMag`
  declaration it shared with the setting-group fixture (see the eleventh pass). `ied sim` prints which trackers a file engineered, and
  `ied scl show` now prints each data object's common data class — which is what made
  `DataObject::cdc` load-bearing instead of parsed-and-never-read.

#### Fixed

- **`ServiceError::from_data_access` had the ISO 9506 codes wrong**, found by the first test
  written against it: `object-access-denied` is 3, not 5, and 0 is `object-invalidated` rather
  than success. A success never reaches that function — `Ok(())` is `NoError` directly.

### Eleventh pass

#### Changed

- ⚠ **A setting-group-dependent setting is published under both `SG` and `SE`** from the one
  declaration SCL allows (D48). The server published only the constraint the file spells, so a
  schema-valid file got an `SG` namespace and **no `SE` namespace at all** — and the whole
  select ▸ write ▸ confirm sequence answered `object-non-existent`. It survived because this
  repository's own fixture declared the attribute twice, once under each constraint, which the
  schema forbids (`uniqueDAorSDOInDOType` makes a `DA` name unique within its `DOType`). Each
  view now carries its **own** functional constraint, or an `SE` node would be refused every
  write by the rule that what is in force changes only by activating a group.
- ⚠ **A unicast sampled-value stream is a `USVCB` under `US`** (D49), with `UsvID` and without
  `noASDU`. `SampledValueControl/@multicast` had been loaded into the model and read by
  nothing, so every stream was published as an `MSVCB` — three wrong answers from one unread
  flag: wrong constraint, an identifier the client cannot find, and a field the block has not
  got.
- **`CnfEdit` is put back to false** once an edit is applied, as `GI` and `PurgeBuf` already
  were. A server that leaves it true answers "is an edit being confirmed?" with yes for ever.
- **The `SGCB`'s `ResvTms` expires the edit reservation.** A client that selects a group and
  then goes quiet without closing its association held a whole logical device's settings for
  good. `ResvTms` is writable by the client that holds the reservation, and — unlike a report
  control block's — this one does **not** outlive the association.

#### Added

- **`FindingCode::DuplicateTypeMember`** — a type template that declares a member name twice
  (`DO` in an `LNodeType`, `DA`/`SDO` in a `DOType`, `BDA` in a `DAType`). The schema forbids
  all three; the loader reads with `roxmltree` and validates nothing against the XSD, so a file
  no validating parser would accept loads here and gives the server two variables of one name
  (D50). Reported once per name, and asserted clean on the OpenSCD corpus.
- **`FindingCode::IndexedReportControl`** — `RptEnabled max` above one on a block that is not
  `indexed`. Instances exist only when a block is indexed, so the file promises a number of
  simultaneous clients the device cannot serve.

### Tenth pass

The finding that drove that one is about the **corpus** rather than the code:
every SCL fixture in this repository built its data sets out of single attributes, so for ten
audits none of them had a data set whose members are data *objects* — the shape most engineering
tools actually write. The server flattened those members into their attributes, the client read
what the server sent, and the two agreed perfectly while the same server's data-set directory
answered with a list of a different length.

#### Changed

- ⚠ **A report is granular in data-set *members*, not in attributes** (D42). A member that names
  a data object — `<FCDA doName="Pos" fc="ST"/>`, with no `daName` — is **one** inclusion bit,
  **one** value and **one** `ReasonCode`, and is carried as the structure it is. It used to be
  flattened into `stVal`, `q` and `t`, which made the inclusion bit string a different length
  from the member list `GetNamedVariableListAttributes` answers with — and a client indexes one
  against the other. `GetDataSetValues` answers one `AccessResult` per member for the same
  reason. Triggers are still evaluated per attribute and merge into the member's reason code.
  `ServedDataSet::members` is now `Vec<DataSetMember>` and `ServedDataSet::leaves` is gone;
  `ServedDataSet::references()` gives the old member-name list.
- ⚠ **`SqNum` is zeroed when a report control block is enabled** (IEC 61850-7-2 §17.2.2), so the
  first report of a subscription no longer carries a number left over from the previous client.
  The counter is the engine's and is written *into* the model, so the attribute a client reads
  is the sequence number of the last report it was sent.
- ⚠ **`ConfRev` moves when `DatSet` does**, and a `DatSet` naming a data set the model has not
  got is refused with `object-value-invalid` rather than stored.
- **A `ResvTms` reservation outlives its association** by the seconds it names ⚠ and is expired
  by the engine's own timer, instead of being released the moment the link drops — which had
  made the attribute a slower `Resv`. `Acsi::on_association_closed` takes a `now` for it.
- **`RptEna` is cleared when the association that set it ends** — with `GI`, `PurgeBuf` and
  `Resv`. The engine dropped its own ownership and the *model* kept saying the block was
  enabled, which is worse than cosmetic: the server refuses every setting while `RptEna` is
  true, so the next client to connect found a block that read as enabled, was owned by nobody,
  and could not be configured without first guessing it had to be turned off. Found by writing
  the reconnection test, not by reading the code. `Owner` is now **recomputed** rather than
  cleared, because a `ResvTms` reservation deliberately outlives its association and while it
  does the block is still that client's.
- ⚠ **An integrity period without its trigger reports nothing.** `IntgPd` is *how often* and
  `TrgOps.integrity` is *whether* (IEC 61850-7-2 §17.2.2); the engine scanned on the period
  alone, so a client that had not asked for integrity reports got them. `ied scl validate` has
  called a period without a trigger a finding since the ninth audit — the engine now agrees with
  the validator about what the file means.
- **A client whose outbound queue fills is disconnected** (D45). The per-association queue for
  reports and command terminations was **unbounded**: a client that stopped reading its socket
  grew it without limit, remotely. It is now bounded by `ServerConfig::outbound_queue` (256 PDUs)
  and overflow closes the association — a buffered control block keeps its entries and the client
  resumes from its `EntryID`, which is what `BR` is for.
- **`GetNameList` pages and reports are sized by the *association's* negotiated PDU**, not by the
  server's own configured maximum. ISO 9506 negotiates down, so the server's figure was an upper
  bound rather than an agreement.
- `Engine::on_write` and `Acsi::on_association_closed` changed signature; `Engine::commit` and
  the report path now return several `Outgoing` where a report is segmented.

#### Added

- ⚠ **Server-side report segmentation** (D43). A report larger than the association's negotiated
  PDU is split into `InformationReport`s sharing `RptID` and `SqNum`, each with its own
  `SubSeqNum`, `MoreSegmentsFollow` on all but the last, and an inclusion bit string naming only
  the members it carries — and the `segmentation` flag set in the `OptFlds` those segments
  publish, because that flag is the only thing that tells a decoder what the two values after
  `ConfRev` are. Before this the server encoded the report whole, the association refused to
  frame anything over the peer's limit, and the connection loop discarded the error: the client
  got no report and no reason. The client has joined segments since M2; now both halves do their
  side. `Engine::set_max_pdu`, `Acsi::set_association_max_pdu`.
- ⚠ **MMS `Status` and `GetCapabilityList`** on both sides — two **M/M** rows that had nothing
  behind them. `Status` needs no name, no data set and no model, so an answer to it is proof all
  six layers are alive: `Client::status`, `Client::is_alive`, `ServerStatus`,
  `AcsiConfig::{vmd_logical_status, vmd_physical_status, capabilities}`, `proto::mms::vmd_logical`
  and `proto::mms::vmd_physical`. `Client::capabilities` pages like every other list here.
  New CLI subcommand `ied mms status`.
- ⚠ **MMS `Cancel`** (D46) — `Mms::{CancelRequest, CancelResponse, CancelError}` and
  `Association::cancel`. This is D35 on a third PDU: a `cancel-RequestPDU` used to fall through to
  the unconfirmed catch-all with **nothing sent back**, so the peer waited out its whole request
  timeout for a reply that was never coming. Every service here is answered in the turn it
  arrives, so there is never anything left to withdraw and the association answers with a
  `cancel-Error` itself. Incoming, a `cancel-Response` releases the invoke — no answer is coming —
  and a `cancel-Error` leaves it outstanding. `AssociationEvent::{Cancelled, CancelRefused}`,
  `ServiceError::encode`, `proto::mms::service_error`.
- **Client reconnection with backoff** (D47) — the last **M** row of the association line.
  `Backoff`, `Client::connect_retrying` and `Client::reconnect`, which restores **nothing**
  silently: a control block, a selection and a file handle all belonged to the association that
  ended, and the buffered block the standard does provide for is resumed by the caller with
  `RcbSettings::resume_after`. `Client::from_stream` cannot reconnect and says so.
- `Ied::read_reference`, `ServedDataSet::{references, len, is_empty}`, `DataSetMember`.
- **`tests/fixtures/fcd.icd`** — a corpus entry whose data sets are made of data objects, which
  is the shape that was missing, plus a twelve-member set that no small PDU can hold.
- **Two more Wireshark oracle assertions** (`tests/tshark_mms.rs`): the new services, and a
  second test that runs a 900-octet client against that twelve-member data set so `tshark` reads
  a *segmented* report carrying *structures*. Both are encodings this crate's own client would
  otherwise be the only reader of.

### Ninth pass

Driven by pointing Wireshark at the station bus for the first time.

#### Added

- **A Wireshark oracle for MMS** (`tests/tshark_mms.rs`). A recording proxy in front of a real
  server, a real client through every service it answers, and the whole association written out
  as a TCP capture for `tshark` to dissect as TPKT ▸ COTP ▸ session ▸ presentation ▸ ACSE ▸
  MMS. It found the three ⚠ defects below on its first run — all of them invisible to a suite
  in which the same codec decoded what it had encoded.
- ⚠ **The GOOSE and sampled-value control blocks are served**, with the nine components each
  has and the address the file's `Communication` section gives them. `DstAddress` is the
  `PhyComAddr` **structure** (`Addr`, `PRIORITY`, `VID`, `APPID`) rather than an octet string,
  and a `PhyComAddr` data attribute is expanded into it everywhere.
- **A write policy on the server.** `Fc::is_client_writable` and
  `server::writable_block_attribute` decide what a *client* may write; the application's own
  `ServerHandle::txn()` is unaffected and remains the only path to `ST` and `MX`.
- **`Owner`** on a report control block now carries the holder's network address
  (`Acsi::on_association_opened`, `Engine::holder`, `Engine::held_by`).
- **`Beh`/`Mod` gating of controls**, with `AddCause::BlockedByMode`, and `Test` required to
  agree with the behaviour in both directions.
- **Log entries carry their reason.** `LogEntry::reason` on the client,
  `journal::REASON_CODE_TAG` on the wire, and `ied mms log` prints it.
- `BType::Octet6`, `BType::Octet16` and `BType::LogOptFlds` — the Edition 2.1 additions to the
  SCL `bType` list, which previously fell through to `BType::Other` and were modelled as
  structures with no components.
- **`LGOS`/`LSVS` subscription supervision** — the last unbuilt **M/M** row of the service
  matrix. `server::SubscriptionStatus::from_goose`/`from_sv` reads a live subscriber's own
  state and `Txn::supervise` publishes it into the logical node the SCL file declares, writing
  only the objects that file has and only when one has actually moved. `IedModel::supervision`
  and `Supervision::watches` read the `GoCBRef`/`SvCBRef` binding out of the file, `ied scl
  subs` prints it, and `examples/supervised_subscriber.rs` runs the whole seam with no network.
  New accessors behind it: `goose::Subscriber::{is_live, conf_rev, needs_commissioning,
  config}` and `sv::StreamState::conf_rev`.
- **`LogStore`** — the server's log entries live behind a trait, with `MemoryLog` (a bounded
  ring) as the default and `Server::set_log_store` to replace it. `LogBounds`, `NewEntry` and
  `Logs::log_references` come with it. The `EntryID` belongs to the store, because it is what a
  client resumes after.
- `acse::DIAGNOSTIC_SERVICE_USER_NULL` and `acse::diagnostic_service_user`.
- **Report and log control blocks are validated** like the publishers: `FindingCode::MissingLog`
  for a `logName` no `Log` defines, `FindingCode::ReportTriggers` for an `intgPd` with no
  integrity trigger (or a trigger with no period), and the existing `MissingDataSet` and
  `ObjectReferenceTooLong` checks now reach them too.
- `common::data_access_reason`, so `Error::DataAccess(3)` prints
  `object-access-denied` rather than a bare number.
- **Feature badges in the API documentation.** `[package.metadata.docs.rs]` documents every
  feature and passes `--cfg docsrs`, so each gated item says which feature unlocks it instead
  of leaving the reader to work it out from the module tree.

#### Fixed

- ⚠ **An `AARE` carried no `result-source-diagnostic`.** The field is mandatory beside
  `result` (X.227), so every association this server accepted was answered with an ACSE PDU a
  positional reader calls malformed. It is now written whenever a result is.
- ⚠ **A `JournalEntry` carried no `originatingApplication`.** Also mandatory; the empty
  `ApplicationReference` is now written, as libiec61850 does.
- ⚠ **`FileDirectory`'s `listOfDirectoryEntry [0]` was implicitly tagged.** It is the one field
  of the MMS file services that is not, so the entries belong inside an inner universal
  `SEQUENCE`. Both halves of this crate had it wrong in the same way and therefore agreed; the
  encoder is fixed and the decoder reads either spelling.
- **A general interrogation on a block nobody had enabled** produced a report with nowhere to
  go, and on a buffered block queued one for the next client to connect. `GI` and `PurgeBuf`
  now require the block to be enabled by the asking association.
- **A buffered block's buffer was a queue, not a ring.** Only the entries made while nobody
  was listening were kept, and enabling the block emptied it — so the last identifier a client
  had actually been sent was never *in* the buffer, and a reconnecting client's resume point
  looked lost. Every entry of a `BR` block now goes into the ring (a general interrogation
  excepted: it answers a request rather than recording an event), the ring is read rather than
  drained, and `EntryID` is a position in it.
- **A buffered block resumed silently from a lost `EntryID`.** A resume point the ring no
  longer holds now raises `BufOvfl` on the first replayed report.
- **A data-set member with no value** was reported as `false`. It is now excluded from the
  report rather than given a placeholder a client would act on.
- **`LogControl/@reasonCode` was parsed and ignored**, so the decision to record a reason was
  taken by a condition that was always true.
- **An `ExtRef` naming only a data object resolved to nothing** when the publisher's data set
  named an attribute of it — `PTRC1.Tr` against a data set of `Tr.general` and `Tr.q`. Both
  spellings are ordinary in a real SCD, and the signal travels in that GOOSE either way, so
  `ied scl subs` reported an unbound input on a file that was entirely correct.
- **Selecting a setting group for editing** marked the edit copy dirty, which could make a
  report claim settings had changed when nothing in force had moved.

#### Changed

- ⚠ **A client can no longer write `ST` or `MX`.** IEC 61850-7-2 §5.7 makes them read-only over
  ACSI, and a server that accepted the write let a client fake a breaker position with no
  breaker involved. The same applies to the counters inside a control block — `SqNum`,
  `ConfRev`, `TimeOfEntry`, `BufOvfl`, `Owner` — while `EntryID` stays writable, because
  writing it is how a client says where to resume.
- **`Fc` gained `is_client_writable`**, `BType` gained three variants, and
  `TypeSpec` for `SvOptFlds` is now a bounded eight-bit string rather than three bits.
- **`Logs` is built on `LogStore`.** `DEFAULT_LOG_CAPACITY` is now the default store's
  capacity rather than the engine's.
- `Client::write_many` (which the control-block and setting-group helpers use) requires each
  reference to carry its own functional constraint instead of defaulting to `ST` — a default
  that is silently wrong now that the constraint decides whether a write is allowed at all.
- **`ied mms write` requires `--fc`.** A read has a sensible default; a write does not, because
  the default that suits a read is the one constraint a conforming server must refuse. The
  missing flag is now an error from the tool rather than `object-access-denied` from the far
  end — an error about the server for a mistake on the command line.

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
- The fuzz smoke job discovers targets with `cargo fuzz list` instead of naming them, so a
  target added to `fuzz/fuzz_targets/` cannot be one nothing runs — `mms_server` was.
- The `sv_publisher` target drives `smpSynch` from the fuzzer's bytes, covering both sides of
  the width boundary and the template re-encode that crossing it triggers.
- `concepts/QUALITY.md` section numbering repaired (it had two `§5.2`s).

## [0.1.0] — 2026-09-06

First release. GOOSE and Sampled Values with sans-IO publishers and subscribers, the OSI stack
and MMS PDUs, the association state machine in both roles, a blocking MMS client and server,
SCL loading and validation, pcap tooling and the `ied` command line.

[Unreleased]: https://github.com/hupe1980/iec61850-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/hupe1980/iec61850-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/hupe1980/iec61850-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hupe1980/iec61850-rs/releases/tag/v0.1.0
