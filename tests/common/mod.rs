//! Shared helpers for the integration tests: a tiny pcap reader and locating `specs/`.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

/// Path to a file under `specs/`, or `None` (tests skip) when the directory is absent —
/// which is what CI sees, because `specs/` is git-ignored.
pub fn spec(rel: &str) -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("specs").join(rel);
    p.is_file().then_some(p)
}

/// Frames of a classic pcap file (link type Ethernet), as `(timestamp_ns, bytes)`.
pub fn read_pcap(path: &Path) -> Vec<(u64, Vec<u8>)> {
    let d = std::fs::read(path).expect("read pcap");
    assert!(d.len() >= 24, "pcap too short");
    let le = match d[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => panic!("not a classic pcap"),
    };
    let nanos = d[0..4] == [0x4d, 0x3c, 0xb2, 0xa1] || d[0..4] == [0xa1, 0xb2, 0x3c, 0x4d];
    let u32_at = |o: usize| {
        let b = [d[o], d[o + 1], d[o + 2], d[o + 3]];
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    assert_eq!(u32_at(20), 1, "link type must be Ethernet");
    let mut out = Vec::new();
    let mut off = 24;
    while off + 16 <= d.len() {
        let ts = u64::from(u32_at(off)) * 1_000_000_000 + u64::from(u32_at(off + 4)) * if nanos { 1 } else { 1000 };
        let cl = u32_at(off + 8) as usize;
        let start = off + 16;
        let end = start + cl;
        if end > d.len() {
            break;
        }
        out.push((ts, d[start..end].to_vec()));
        off = end;
    }
    out
}

/// Write frames as a classic pcap (Ethernet, microsecond timestamps).
pub fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        out.extend_from_slice(&(1_700_000_000u32).to_le_bytes());
        out.extend_from_slice(&((i as u32) * 1000).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    std::fs::write(path, out).expect("write pcap");
}

/// The oldest Wireshark whose verdict about a GOOSE frame can be believed.
///
/// Up to 4.2.2 the GOOSE dissector asserts `recursion_depth <= 100` on a **legitimate**
/// message and marks it `_ws.malformed` (wireshark#19580, fixed in 4.2.3). An oracle that
/// reports correct frames as malformed is testing itself, not us — and Ubuntu 24.04 ships
/// exactly 4.2.2, so this is not a hypothetical.
const TSHARK_MIN: (u32, u32, u32) = (4, 2, 3);

/// `tshark`, if it is installed and new enough to be trusted. `None` means the tests that
/// use it skip.
///
/// Set `IEC61850_REQUIRE_TSHARK=1` to make both of those a failure instead. CI does, because
/// a silent skip would let the Wireshark oracle stop running without anyone noticing — which
/// is the one thing an oracle must not be able to do.
pub fn tshark() -> Option<PathBuf> {
    let required = std::env::var("IEC61850_REQUIRE_TSHARK").is_ok_and(|v| v != "0");
    let out = std::process::Command::new("sh").arg("-c").arg("command -v tshark").output().ok()?;
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() || path.is_empty() {
        assert!(!required, "IEC61850_REQUIRE_TSHARK is set, but tshark is not installed");
        return None;
    }
    let path = PathBuf::from(path);
    let Some(version) = tshark_version(&path) else {
        assert!(!required, "IEC61850_REQUIRE_TSHARK is set, but `tshark -v` did not report a version");
        return None;
    };
    if version < TSHARK_MIN {
        let (found, want) = (dotted(version), dotted(TSHARK_MIN));
        assert!(!required, "IEC61850_REQUIRE_TSHARK is set, but tshark {found} is older than {want} (wireshark#19580)");
        eprintln!("skipping: tshark {found} is older than {want}, which reports valid GOOSE frames as malformed (wireshark#19580)");
        return None;
    }
    Some(path)
}

fn dotted(version: (u32, u32, u32)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}

/// The `major.minor.patch` out of `TShark (Wireshark) 4.2.3 (v4.2.3-0-g...)`.
fn tshark_version(path: &Path) -> Option<(u32, u32, u32)> {
    let out = std::process::Command::new(path).arg("-v").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    first.split_whitespace().find_map(|word| {
        let mut parts = word.trim_start_matches('v').split('.');
        let v = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
        parts.next().is_none().then_some(v)
    })
}

// ---------------------------------------------------------------------------------------
// A minimal MMS server, for the tests that need something to talk to.
//
// It is the crate's own `Association` in the server role with a handful of canned answers —
// which is the point of the sans-IO shape: a second end costs a hundred lines rather than a
// second implementation, and both the library client and the `ied` binary can be driven
// against it without a network or a vendor device.
// ---------------------------------------------------------------------------------------

#[cfg(feature = "client")]
mod mms_server {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use iec61850_rs::ber::Cursor;
    use iec61850_rs::common::{EntryTime, Instant, Limits, Quality, TimeQuality, UtcTime};
    use iec61850_rs::proto::data::{Dbpos, Typed, Value};
    use iec61850_rs::proto::mms::association::{Association, AssociationConfig, AssociationEvent};
    use iec61850_rs::proto::mms::control::{AddCause, ControlError, ControlRequest, LastApplError, Origin, OriginCategory};
    use iec61850_rs::proto::mms::file::{DirectoryEntry, FileAttributes, FileNameBuf};
    use iec61850_rs::proto::mms::journal::{JournalEntry, JournalVariable, TimeOfDay};
    use iec61850_rs::proto::mms::report::{OptFlds, ReasonCode, Report, ReportEntry, TrgOps};
    use iec61850_rs::proto::mms::typespec::{Component, TypeSpec};
    use iec61850_rs::proto::mms::{
        AccessResult, ConfirmedRequest, ConfirmedResponse, Mms, ObjectName, ObjectScope, Unconfirmed, VariableAccess, VariableSpecification, WriteResult,
        object_class,
    };

    /// What the server pretends to be: one logical device, three variables, one data set,
    /// one unbuffered report control block and one controllable double point.
    const LD: &str = "IED1LD0";
    const RCB: &str = "LLN0$RP$urcb01";
    const DATA_SET: &str = "IED1LD0/LLN0$dsTrip";
    /// The data set's members, which is what an inclusion bit string indexes into.
    const MEMBERS: [&str; 2] = ["IED1LD0/PTRC1$ST$Tr$general", "IED1LD0/PTRC1$ST$Tr$q"];
    const CONTROL: &str = "CSWI1$CO$Pos";
    /// The one file the server pretends to have, and its contents.
    const FILE: &str = "COMTRADE/rec0001.cfg";
    const FILE_BODY: &[u8] = b"STATION,IED1,2013\n3,3A,0D\n";
    /// The log, and the two entries in it.
    const LOG: &str = "LLN0$GeneralLog";

    /// How the spawned server should behave, so one harness covers every test.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct ServerBehaviour {
        /// Reports to push out the moment reporting is enabled.
        pub reports: usize,
        /// Answer a control with a negative command termination carrying this cause.
        pub refuse_control: Option<AddCause>,
        /// The control object needs a select first, and answers with a termination.
        pub enhanced_control: bool,
        /// Send a termination for a *different* `ctlNum` first, which a client must not
        /// mistake for the answer to the command it is waiting on.
        pub stale_termination: bool,
        /// Split every report into one segment per data-set member.
        pub segment_reports: bool,
    }

    struct Server {
        assoc: Association,
        /// The report control block, attribute by attribute — which is how a real one is
        /// addressed, and the only way that survives an Edition difference.
        rcb: Vec<(&'static str, Value)>,
        selected: bool,
        pending_reports: usize,
        behaviour: ServerBehaviour,
        seq: u32,
        /// Open file handles, as `(frsmID, bytes already delivered)`.
        files: Vec<(i32, usize)>,
        next_frsm: i32,
        /// Data sets created over this association.
        created: Vec<String>,
        /// The setting group control block, attribute by attribute.
        sgcb: Vec<(&'static str, Value)>,
        /// How many times an edit was confirmed.
        confirmed: usize,
    }

    impl Server {
        fn new(behaviour: ServerBehaviour) -> Server {
            Server {
                assoc: Association::server(AssociationConfig::default()),
                rcb: alloc_rcb(),
                selected: false,
                pending_reports: 0,
                behaviour,
                seq: 0,
                files: Vec::new(),
                next_frsm: 7,
                created: Vec::new(),
                sgcb: alloc_sgcb(),
                confirmed: 0,
            }
        }

        fn rcb_get(&self, attribute: &str) -> Option<&Value> {
            self.rcb.iter().find(|(a, _)| *a == attribute).map(|(_, v)| v)
        }

        fn rcb_set(&mut self, attribute: &str, value: Value) -> bool {
            // A real server refuses every write but `RptEna` and `GI` while reporting is on.
            let enabled = self.rcb_get("RptEna").and_then(Typed::as_bool).unwrap_or(false);
            if enabled && !matches!(attribute, "RptEna" | "GI") {
                return false;
            }
            match self.rcb.iter_mut().find(|(a, _)| *a == attribute) {
                Some(slot) => {
                    slot.1 = value;
                    true
                }
                None => false,
            }
        }
    }

    impl Server {
        fn sgcb_get(&self, attribute: &str) -> Option<Value> {
            self.sgcb.iter().find(|(a, _)| *a == attribute).map(|(_, v)| v.clone())
        }

        fn sgcb_set(&mut self, attribute: &str, value: Value) -> bool {
            match self.sgcb.iter_mut().find(|(a, _)| *a == attribute) {
                Some(slot) => {
                    // Confirming an edit puts the edit group into force, which is what a real
                    // device does and what makes the ordering testable.
                    if attribute == "CnfEdit" && value.as_bool() == Some(true) {
                        self.confirmed += 1;
                    }
                    slot.1 = value;
                    true
                }
                None => false,
            }
        }
    }

    fn alloc_sgcb() -> Vec<(&'static str, Value)> {
        vec![
            ("NumOfSG", Value::Unsigned(4)),
            ("ActSG", Value::Unsigned(1)),
            ("EditSG", Value::Unsigned(0)),
            ("CnfEdit", Value::Boolean(false)),
            ("LActTm", Value::BinaryTime(EntryTime::from_unix_millis(1_700_000_000_000).to_octets().to_vec())),
            ("ResvTms", Value::Integer(30)),
        ]
    }

    /// The log control block a `read_lcb` sees.
    fn lcb_get(attribute: &str) -> Option<Value> {
        Some(match attribute {
            "LogEna" => Value::Boolean(true),
            "LogRef" => Value::VisibleString(format!("{LD}/{LOG}")),
            "DatSet" => Value::VisibleString(String::from(DATA_SET)),
            "OldEntrTm" => Value::BinaryTime(EntryTime::from_unix_millis(1_700_000_000_000).to_octets().to_vec()),
            "NewEntrTm" => Value::BinaryTime(EntryTime::from_unix_millis(1_700_000_060_000).to_octets().to_vec()),
            "OldEnt" => Value::OctetString(vec![0, 0, 0, 0, 0, 0, 0, 1]),
            "NewEnt" => Value::OctetString(vec![0, 0, 0, 0, 0, 0, 0, 2]),
            "TrgOps" => TrgOps::EVENTS.to_value(),
            "IntgPd" => Value::Unsigned(0),
            _ => return None,
        })
    }

    fn alloc_rcb() -> Vec<(&'static str, Value)> {
        vec![
            ("RptID", Value::VisibleString(String::from("IED1LD0/LLN0$RP$urcb01"))),
            ("RptEna", Value::Boolean(false)),
            ("DatSet", Value::VisibleString(String::from(DATA_SET))),
            ("ConfRev", Value::Unsigned(3)),
            ("OptFlds", OptFlds::NONE.to_value()),
            ("BufTm", Value::Unsigned(0)),
            ("SqNum", Value::Unsigned(0)),
            ("TrgOps", TrgOps::NONE.to_value()),
            ("IntgPd", Value::Unsigned(0)),
            ("GI", Value::Boolean(false)),
            ("Resv", Value::Boolean(false)),
        ]
    }

    fn serve(mut stream: TcpStream, behaviour: ServerBehaviour) {
        let mut s = Server::new(behaviour);
        s.pending_reports = behaviour.reports;
        let mut buf = [0u8; 4096];
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            s.assoc.on_bytes(Instant::ZERO, &buf[..n]);
            let mut requests: Vec<(i64, Vec<u8>)> = Vec::new();
            let mut established = false;
            while let Some(event) = s.assoc.poll_event() {
                match event {
                    AssociationEvent::Established(_) => established = true,
                    AssociationEvent::Request { invoke_id, pdu } => requests.push((invoke_id, pdu)),
                    AssociationEvent::Closed(_) => {
                        let _ = flush(&mut s.assoc, &mut stream);
                        return;
                    }
                    other => panic!("server saw {other:?}"),
                }
            }
            for (invoke_id, pdu) in requests {
                answer(&mut s, invoke_id, &pdu);
            }
            // Reports go out once reporting is on — which for the "arrives during a request"
            // test means the moment the association comes up, before anything is asked.
            let enabled = s.rcb_get("RptEna").and_then(Typed::as_bool).unwrap_or(false);
            if (established || enabled) && s.pending_reports > 0 {
                let due = s.pending_reports;
                s.pending_reports = 0;
                for _ in 0..due {
                    send_report(&mut s, ReasonCode::NONE.with_data_change(true));
                }
            }
            if flush(&mut s.assoc, &mut stream).is_err() {
                return;
            }
        }
    }

    /// Build and send a real IEC 61850 report: the header its `OptFlds` promises, the
    /// inclusion bit string, then the values.
    fn send_report(s: &mut Server, reason: ReasonCode) {
        s.seq = s.seq.wrapping_add(1);
        let opt_flds = OptFlds::from_value(s.rcb_get("OptFlds").unwrap()).unwrap_or(OptFlds::NONE);
        let entries = vec![
            ReportEntry {
                index: 0,
                reference: opt_flds.data_reference().then(|| String::from(MEMBERS[0])),
                value: Value::Boolean(true),
                reason: opt_flds.reason_for_inclusion().then_some(reason),
            },
            ReportEntry {
                index: 1,
                reference: opt_flds.data_reference().then(|| String::from(MEMBERS[1])),
                value: Value::quality(Quality::GOOD),
                reason: opt_flds.reason_for_inclusion().then_some(reason),
            },
        ];
        let report = Report {
            rpt_id: s.rcb_get("RptID").and_then(Typed::as_str).unwrap_or_default().to_string(),
            opt_flds,
            seq_num: opt_flds.sequence_number().then_some(s.seq),
            time_of_entry: opt_flds.report_time_stamp().then(|| EntryTime::from_unix_millis(1_700_000_000_000 + u64::from(s.seq))),
            data_set: opt_flds.data_set_name().then(|| String::from(DATA_SET)),
            buf_ovfl: opt_flds.buffer_overflow().then_some(false),
            entry_id: opt_flds.entry_id().then(|| vec![0, 0, 0, 0, 0, 0, 0, s.seq as u8]),
            conf_rev: opt_flds.conf_revision().then_some(3),
            sub_seq_num: None,
            more_segments_follow: false,
            inclusion: Report::inclusion_for(MEMBERS.len(), &[0, 1]),
            entries,
        };
        let access = VariableAccess::VariableListName(ObjectName::DomainSpecific { domain: LD, item: RCB });
        if !s.behaviour.segment_reports {
            let values = report.to_values().expect("build report");
            send_information_report(s, access, &values);
            return;
        }
        // One segment per data-set member: each carries its own inclusion bit string naming
        // only what is in it, and only the last says nothing more follows.
        let total = report.entries.len();
        for (n, entry) in report.entries.iter().enumerate() {
            let mut segment = report.clone();
            segment.opt_flds = segment.opt_flds.with_segmentation(true);
            segment.sub_seq_num = Some(n as u32);
            segment.more_segments_follow = n + 1 < total;
            segment.inclusion = Report::inclusion_for(MEMBERS.len(), &[entry.index]);
            segment.entries = vec![entry.clone()];
            let values = segment.to_values().expect("build segment");
            send_information_report(s, access.clone(), &values);
        }
    }

    /// Send an `InformationReport` naming a variable list, with these values.
    fn send_information_report(s: &mut Server, access: VariableAccess<'_>, values: &[Value]) {
        let encoded: Vec<Vec<u8>> = values.iter().map(|v| Value::encode_all(std::slice::from_ref(v)).unwrap()).collect();
        let results: Vec<AccessResult<'_>> = encoded.iter().map(|b| AccessResult::Success(Cursor::new(b).next_required().unwrap())).collect();
        s.assoc.send(&Mms::Unconfirmed(Unconfirmed::InformationReport { access, results })).unwrap();
    }

    /// A command termination: the `Oper` alone when positive, `LastApplError` first when not.
    fn send_termination(s: &mut Server, request: &ControlRequest, cause: Option<AddCause>) {
        let oper = format!("{LD}/{CONTROL}$Oper");
        match cause {
            None => {
                let item = format!("{CONTROL}$Oper");
                let names = vec![VariableSpecification::Name(ObjectName::DomainSpecific { domain: LD, item: &item })];
                send_information_report(s, VariableAccess::ListOfVariable(names), &[request.to_value()]);
            }
            Some(cause) => {
                let error = LastApplError {
                    control_object: oper,
                    error: ControlError::Unknown,
                    origin: request.origin.clone(),
                    ctl_num: request.ctl_num,
                    add_cause: cause,
                };
                let item = format!("{CONTROL}$Oper");
                let names = vec![
                    VariableSpecification::Name(ObjectName::VmdSpecific("LastApplError")),
                    VariableSpecification::Name(ObjectName::DomainSpecific { domain: LD, item: &item }),
                ];
                send_information_report(s, VariableAccess::ListOfVariable(names), &[error.to_value(), request.to_value()]);
            }
        }
    }

    fn flush(a: &mut Association, stream: &mut TcpStream) -> std::io::Result<()> {
        while let Some(packet) = a.poll_transmit() {
            let packet = packet.to_vec();
            // Deliberately in small pieces: TCP is a stream and a client that only works when
            // a PDU arrives whole is a client that works on a lab bench and nowhere else.
            for chunk in packet.chunks(7) {
                stream.write_all(chunk)?;
            }
        }
        stream.flush()
    }

    /// The MMS item of a domain-specific name, or `None`.
    fn item_of<'a>(spec: &VariableSpecification<'a>) -> Option<&'a str> {
        match spec {
            VariableSpecification::Name(ObjectName::DomainSpecific { item, .. }) => Some(item),
            _ => None,
        }
    }

    // One arm per MMS service the server answers; splitting it would hide the table.
    #[allow(clippy::too_many_lines)]
    fn answer(s: &mut Server, invoke_id: i64, pdu: &[u8]) {
        let Mms::ConfirmedRequest { service, .. } = Mms::parse(pdu, &Limits::DEFAULT).unwrap() else {
            panic!("not a request");
        };
        match service {
            ConfirmedRequest::Identify => {
                s.assoc.respond(invoke_id, &ConfirmedResponse::Identify { vendor: "hupe1980", model: "iec61850-rs", revision: "0.1.0" }).unwrap();
            }
            ConfirmedRequest::GetNameList { object_class: class, scope, continue_after } => {
                let (names, more): (&[&str], bool) = match (class, scope, continue_after) {
                    (object_class::DOMAIN, ObjectScope::VmdSpecific, None) => (&["IED1LD0"], false),
                    // Paged on purpose: the client has to ask again with `continue_after`.
                    (object_class::NAMED_VARIABLE, ObjectScope::DomainSpecific("IED1LD0"), None) => (&["LLN0$ST$Beh$stVal", "MMXU1$MX$TotW$mag$f"], true),
                    (object_class::NAMED_VARIABLE, ObjectScope::DomainSpecific("IED1LD0"), Some("MMXU1$MX$TotW$mag$f")) => (&["PTRC1$ST$Tr$general"], false),
                    (object_class::NAMED_VARIABLE_LIST, ObjectScope::DomainSpecific("IED1LD0"), None) => (&["LLN0$dsTrip"], false),
                    _ => (&[], false),
                };
                s.assoc.respond(invoke_id, &ConfirmedResponse::GetNameList { identifiers: names.to_vec(), more_follows: more }).unwrap();
            }
            ConfirmedRequest::GetNamedVariableListAttributes(_) => {
                s.assoc
                    .respond(
                        invoke_id,
                        &ConfirmedResponse::GetNamedVariableListAttributes {
                            deletable: false,
                            variables: vec![VariableSpecification::Name(ObjectName::DomainSpecific { domain: LD, item: "PTRC1$ST$Tr$general" })],
                        },
                    )
                    .unwrap();
            }
            ConfirmedRequest::Read { access, .. } => read(s, invoke_id, &access),
            ConfirmedRequest::Write { access, values } => write(s, invoke_id, &access, &values),
            ConfirmedRequest::GetVariableAccessAttributes(name) => {
                let item = match name {
                    ObjectName::DomainSpecific { item, .. } => item,
                    _ => "",
                };
                let type_spec = if item.ends_with("$Oper") { oper_type() } else { TypeSpec::FloatingPoint { format_width: 32, exponent_width: 8 } };
                s.assoc.respond(invoke_id, &ConfirmedResponse::GetVariableAccessAttributes { deletable: false, type_spec }).unwrap();
            }
            ConfirmedRequest::DefineNamedVariableList { name, variables } => {
                assert!(!variables.is_empty(), "a data set with no members is not one");
                if let ObjectName::DomainSpecific { domain, item } = name {
                    s.created.push(format!("{domain}/{item}"));
                }
                s.assoc.respond(invoke_id, &ConfirmedResponse::DefineNamedVariableList).unwrap();
            }
            ConfirmedRequest::DeleteNamedVariableList { names, .. } => {
                let wanted: Vec<String> = names
                    .iter()
                    .filter_map(|n| match n {
                        ObjectName::DomainSpecific { domain, item } => Some(format!("{domain}/{item}")),
                        _ => None,
                    })
                    .collect();
                let before = s.created.len();
                s.created.retain(|c| !wanted.contains(c));
                let deleted = (before - s.created.len()) as u32;
                // A data set engineered in the SCD is matched and refused; one this client
                // created is deleted. That difference is the whole answer.
                let matched = if deleted > 0 { deleted } else { u32::from(wanted.iter().any(|w| w.ends_with(&format!("/{}", "LLN0$dsTrip")))) };
                s.assoc.respond(invoke_id, &ConfirmedResponse::DeleteNamedVariableList { matched, deleted }).unwrap();
            }
            ConfirmedRequest::FileDirectory { continue_after, .. } => {
                // One file, and the listing is paged: the first answer says more follows.
                let name = FileNameBuf::from_path(FILE).unwrap();
                let (entries, more) = if continue_after.is_some() {
                    (Vec::new(), false)
                } else {
                    (
                        vec![DirectoryEntry {
                            name: name.as_name(),
                            attributes: FileAttributes { size: FILE_BODY.len() as u32, last_modified: Some("20240131T101500Z") },
                        }],
                        true,
                    )
                };
                s.assoc.respond(invoke_id, &ConfirmedResponse::FileDirectory { entries, more_follows: more }).unwrap();
            }
            ConfirmedRequest::FileOpen { name, .. } => {
                assert_eq!(name.display(), FILE, "the server has exactly one file");
                let frsm_id = s.next_frsm;
                s.next_frsm += 1;
                s.files.push((frsm_id, 0));
                s.assoc
                    .respond(
                        invoke_id,
                        &ConfirmedResponse::FileOpen {
                            frsm_id,
                            attributes: FileAttributes { size: FILE_BODY.len() as u32, last_modified: Some("20240131T101500Z") },
                        },
                    )
                    .unwrap();
            }
            ConfirmedRequest::FileRead(frsm_id) => {
                // Deliberately in small chunks, so the client's loop is exercised.
                const CHUNK: usize = 8;
                let slot = s.files.iter_mut().find(|(id, _)| *id == frsm_id).expect("read of a handle that was never opened");
                let start = slot.1;
                let end = (start + CHUNK).min(FILE_BODY.len());
                slot.1 = end;
                let more = end < FILE_BODY.len();
                s.assoc.respond(invoke_id, &ConfirmedResponse::FileRead { data: &FILE_BODY[start..end], more_follows: more }).unwrap();
            }
            ConfirmedRequest::FileClose(frsm_id) => {
                let before = s.files.len();
                s.files.retain(|(id, _)| *id != frsm_id);
                assert_eq!(s.files.len() + 1, before, "close of a handle that was never opened");
                s.assoc.respond(invoke_id, &ConfirmedResponse::FileClose).unwrap();
            }
            ConfirmedRequest::FileDelete(name) => {
                assert_eq!(name.display(), FILE);
                s.assoc.respond(invoke_id, &ConfirmedResponse::FileDelete).unwrap();
            }
            ConfirmedRequest::ReadJournal(request) => {
                let name = match request.name {
                    Some(ObjectName::DomainSpecific { domain, item }) => format!("{domain}/{item}"),
                    _ => String::new(),
                };
                assert_eq!(name, format!("{LD}/{LOG}"), "the server has exactly one log");
                // The first query answers with entry 1 and says more follows; the resume
                // query answers with entry 2 and stops.
                let resuming = request.after.is_some();
                let value = Value::encode_all(&[Value::Boolean(true)]).unwrap();
                let tlv = Cursor::new(&value).next_required().unwrap();
                let occurred = TimeOfDay::from_unix_millis(1_700_000_000_000);
                let entries = if resuming {
                    vec![JournalEntry::annotated(&[0, 0, 0, 0, 0, 0, 0, 2], occurred, "power up")]
                } else {
                    vec![JournalEntry::new(&[0, 0, 0, 0, 0, 0, 0, 1], occurred, vec![JournalVariable { tag: MEMBERS[0], value: tlv }])]
                };
                s.assoc.respond(invoke_id, &ConfirmedResponse::ReadJournal { entries, more_follows: !resuming }).unwrap();
            }
            ConfirmedRequest::Other(_) => panic!("unexpected service"),
        }
    }

    /// The type a server answers for a control object's `Oper`.
    fn oper_type() -> TypeSpec {
        TypeSpec::Structure {
            packed: false,
            components: vec![
                Component { name: Some(String::from("ctlVal")), type_spec: TypeSpec::BitString(2) },
                Component {
                    name: Some(String::from("origin")),
                    type_spec: TypeSpec::Structure {
                        packed: false,
                        components: vec![
                            Component { name: Some(String::from("orCat")), type_spec: TypeSpec::Integer(8) },
                            Component { name: Some(String::from("orIdent")), type_spec: TypeSpec::OctetString(-64) },
                        ],
                    },
                },
                Component { name: Some(String::from("ctlNum")), type_spec: TypeSpec::Unsigned(8) },
                Component { name: Some(String::from("T")), type_spec: TypeSpec::UtcTime },
                Component { name: Some(String::from("Test")), type_spec: TypeSpec::Boolean },
                Component { name: Some(String::from("Check")), type_spec: TypeSpec::BitString(2) },
            ],
        }
    }

    fn read(s: &mut Server, invoke_id: i64, access: &VariableAccess<'_>) {
        let names: Vec<Option<String>> = match access {
            VariableAccess::ListOfVariable(v) => v.iter().map(|spec| item_of(spec).map(String::from)).collect(),
            VariableAccess::VariableListName(_) => vec![None],
        };
        let mut owned: Vec<Option<Value>> = Vec::with_capacity(names.len());
        for name in &names {
            owned.push(match name.as_deref() {
                Some(item) if item.starts_with(RCB) => {
                    let attribute = item.rsplit('$').next().unwrap_or("");
                    s.rcb_get(attribute).cloned()
                }
                Some(item) if item.starts_with("LLN0$SP$SGCB") => {
                    let attribute = item.rsplit('$').next().unwrap_or("");
                    s.sgcb_get(attribute)
                }
                Some(item) if item.starts_with("LLN0$LG$lcb01") => {
                    let attribute = item.rsplit('$').next().unwrap_or("");
                    lcb_get(attribute)
                }
                Some(item) if item == format!("{CONTROL}$SBO") => {
                    // A select is granted by answering with the object reference and refused
                    // by answering with an empty string.
                    s.selected = true;
                    Some(Value::VisibleString(format!("{LD}/{CONTROL}")))
                }
                // Anything else is a measurement.
                _ => Some(Value::Float32(1.5)),
            });
        }
        let encoded: Vec<Option<Vec<u8>>> = owned.iter().map(|v| v.as_ref().map(|v| Value::encode_all(std::slice::from_ref(v)).unwrap())).collect();
        let results: Vec<AccessResult<'_>> = encoded
            .iter()
            .map(|b| match b {
                // 10 is object-non-existent, which is what a server answers for an attribute
                // its edition does not have.
                None => AccessResult::Failure(10),
                Some(bytes) => AccessResult::Success(Cursor::new(bytes).next_required().unwrap()),
            })
            .collect();
        s.assoc.respond(invoke_id, &ConfirmedResponse::Read { access: None, results }).unwrap();
    }

    fn write(s: &mut Server, invoke_id: i64, access: &VariableAccess<'_>, values: &[iec61850_rs::ber::Tlv<'_>]) {
        let names: Vec<Option<String>> = match access {
            VariableAccess::ListOfVariable(v) => v.iter().map(|spec| item_of(spec).map(String::from)).collect(),
            VariableAccess::VariableListName(_) => vec![None],
        };
        let mut outcomes = Vec::with_capacity(names.len());
        let mut fire_gi = false;
        let mut control: Option<(String, ControlRequest)> = None;
        for (name, tlv) in names.iter().zip(values) {
            let value = iec61850_rs::proto::data::DataView::from_tlv(*tlv).unwrap().to_owned(&Limits::DEFAULT).unwrap();
            match name.as_deref() {
                Some(item) if item.starts_with(RCB) => {
                    let attribute = item.rsplit('$').next().unwrap_or("").to_string();
                    if attribute == "GI" && value.as_bool() == Some(true) {
                        fire_gi = true;
                        outcomes.push(WriteResult::Success);
                    } else if s.rcb_set(&attribute, value) {
                        outcomes.push(WriteResult::Success);
                    } else {
                        // 3 is object-access-denied, which is what a server answers when a
                        // control block is enabled.
                        outcomes.push(WriteResult::Failure(3));
                    }
                }
                Some(item) if item.starts_with("LLN0$SP$SGCB") => {
                    let attribute = item.rsplit('$').next().unwrap_or("").to_string();
                    if s.sgcb_set(&attribute, value) { outcomes.push(WriteResult::Success) } else { outcomes.push(WriteResult::Failure(3)) }
                }
                Some(item) if item.starts_with(CONTROL) => {
                    let attribute = item.rsplit('$').next().unwrap_or("").to_string();
                    match ControlRequest::from_value(&value) {
                        Ok(r) => {
                            if attribute == "SBOw" {
                                s.selected = true;
                            }
                            control = Some((attribute, r));
                            outcomes.push(WriteResult::Success);
                        }
                        Err(_) => outcomes.push(WriteResult::Failure(11)),
                    }
                }
                _ => outcomes.push(WriteResult::Success),
            }
        }
        s.assoc.respond(invoke_id, &ConfirmedResponse::Write(outcomes)).unwrap();
        if fire_gi {
            send_report(s, ReasonCode::NONE.with_general_interrogation(true));
        }
        if let Some((attribute, request)) = control {
            if attribute == "Oper" && s.behaviour.enhanced_control {
                if s.behaviour.stale_termination {
                    let mut other = request.clone();
                    other.ctl_num = request.ctl_num.wrapping_add(100);
                    send_termination(s, &other, None);
                }
                send_termination(s, &request, s.behaviour.refuse_control);
            }
        }
    }

    /// Start a server on an ephemeral port and return the address to connect to.
    pub fn spawn(reports: usize) -> String {
        spawn_with(ServerBehaviour { reports, ..ServerBehaviour::default() })
    }

    /// Start a server that behaves as `behaviour` says.
    pub fn spawn_with(behaviour: ServerBehaviour) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                serve(stream, behaviour);
            }
        });
        addr
    }

    /// Constants the tests assert against.
    pub const RCB_REFERENCE: &str = "IED1LD0/LLN0$RP$urcb01";
    /// The controllable object the server exposes.
    pub const CONTROL_REFERENCE: &str = "IED1LD0/CSWI1.Pos";
    /// The data set the report control block reports.
    pub const DATA_SET_REFERENCE: &str = DATA_SET;
    /// The one file the server serves, and its contents.
    pub const FILE_REFERENCE: &str = FILE;
    pub const FILE_CONTENTS: &[u8] = FILE_BODY;
    /// The one log the server serves.
    pub const LOG_REFERENCE: &str = "IED1LD0/LLN0$GeneralLog";
    /// Its log control block.
    pub const LCB_REFERENCE: &str = "IED1LD0/LLN0$LG$lcb01";
    /// The setting group control block.
    pub const SGCB_REFERENCE: &str = "IED1LD0/LLN0$SP$SGCB";

    /// Silence the unused warnings for the items only some test files use.
    #[allow(dead_code)]
    fn _unused(_: Dbpos, _: UtcTime, _: TimeQuality, _: Origin, _: OriginCategory) {}
}

#[allow(unused_imports)]
pub use mms_server::{
    CONTROL_REFERENCE, DATA_SET_REFERENCE, FILE_CONTENTS, FILE_REFERENCE, LCB_REFERENCE, LOG_REFERENCE, RCB_REFERENCE, SGCB_REFERENCE, ServerBehaviour,
    spawn as spawn_mms_server, spawn_with as spawn_mms_server_with,
};
