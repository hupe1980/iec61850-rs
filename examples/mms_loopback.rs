//! A real MMS client against a real MMS server, over a loopback socket.
//!
//! ```text
//! cargo run --example mms_loopback
//! ```
//!
//! Needs no IED, no network and no configuration: the server below is this crate's own
//! [`Association`] in the server role, which is what makes the whole station bus testable
//! without a device. The client half is exactly what you would point at a substation.

use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use iec61850_rs::Fc;
use iec61850_rs::ber::Cursor;
use iec61850_rs::client::{Check, Client, ControlModel, OriginCategory, RcbSettings, TrgOps};
use iec61850_rs::common::{EntryTime, Instant, Limits, Quality};
use iec61850_rs::proto::data::{Dbpos, Typed, Value};
use iec61850_rs::proto::mms::association::{Association, AssociationConfig, AssociationEvent};
use iec61850_rs::proto::mms::control::ControlRequest;
use iec61850_rs::proto::mms::report::{OptFlds, ReasonCode, Report, ReportEntry};
use iec61850_rs::proto::mms::{
    AccessResult, ConfirmedRequest, ConfirmedResponse, Mms, ObjectName, ObjectScope, Unconfirmed, VariableAccess, VariableSpecification, WriteResult,
    object_class,
};

const LD: &str = "IED1LD0";
const RCB: &str = "IED1LD0/LLN0$RP$urcb01";
const CONTROL: &str = "IED1LD0/CSWI1.Pos";

fn main() -> Result<(), Box<dyn Error>> {
    let addr = spawn_server()?;
    println!("server listening on {addr}\n");

    // One call opens TPKT, COTP, session, presentation, ACSE and the MMS Initiate.
    let mut c = Client::connect(&addr)?;
    let negotiated = c.negotiated().ok_or("no negotiated parameters")?;
    println!("associated: max PDU {} octets, {} outstanding", negotiated.max_pdu, negotiated.max_outstanding);

    let id = c.identify()?;
    println!("server is {} {} {}\n", id.vendor, id.model, id.revision);

    // --- browse -------------------------------------------------------------------------
    for ld in c.server_directory()? {
        println!("{ld}");
        for name in c.logical_device_directory(&ld)? {
            println!("  {name}");
        }
        for set in c.data_set_directory(&ld)? {
            println!("  data set {set}");
            for member in c.data_set_members(&ld, &set)? {
                println!("    {member}");
            }
        }
    }

    // --- read and write -----------------------------------------------------------------
    let power = c.read("IED1LD0/MMXU1.TotW.mag.f", Fc::MX)?;
    println!("\nMMXU1.TotW.mag.f = {:?}", power.as_f64());
    c.write("IED1LD0/GGIO1.SPCSO1.stVal", Fc::ST, &Value::Boolean(true))?;
    println!("GGIO1.SPCSO1.stVal <- true");

    // --- reporting ----------------------------------------------------------------------
    // Which fields a report carries is decided entirely by `OptFlds`, so the code that
    // enables the block is what knows how to read what it sends.
    let rcb = c.enable_rcb(RCB, Fc::RP, &RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS))?;
    println!("\nenabled {} on data set {}", rcb.reference, rcb.data_set.as_deref().unwrap_or("-"));
    c.general_interrogation(RCB, Fc::RP)?;

    while let Some(r) = c.next_report(Duration::from_millis(500))? {
        println!("report {} sq={:?}, {} of {} members", r.rpt_id, r.seq_num, r.entries.len(), r.data_set_len());
        for e in &r.entries {
            // `Typed` reads a member as the 7-3 type it claims to be, and returns `None`
            // rather than coercing — an integer where a boolean was engineered is a fault.
            let shown = match (e.value.as_bool(), e.value.as_quality()) {
                (Some(b), _) => format!("{b}"),
                (_, Some(q)) => format!("quality {:?}", q.validity),
                _ => format!("{:?}", e.value),
            };
            println!("  [{}] {shown}  reason {:?}", e.index, e.reason);
        }
    }
    c.disable_rcb(RCB, Fc::RP)?;

    // --- control ------------------------------------------------------------------------
    // Select-before-operate with enhanced security: SBOw, then Oper, then wait for the
    // CommandTermination that says whether the switchgear actually moved.
    println!("\noperating {CONTROL}");
    match c
        .control(CONTROL)
        .model(ControlModel::SboEnhanced)
        .origin(OriginCategory::StationControl, "example")
        .check(Check { synchro: false, interlock: true })
        .timeout(Duration::from_secs(2))
        .execute(&Value::dbpos(Dbpos::On))
    {
        Ok(Some(t)) => println!("command terminated + for {}", t.control_object()),
        Ok(None) => println!("accepted"),
        // A refused command is a refusal, not a successful write.
        Err(iec61850_rs::Error::ControlRejected { add_cause }) => {
            println!("refused: {:?}", iec61850_rs::client::AddCause::from_code(add_cause));
        }
        Err(e) => return Err(e.into()),
    }

    c.release()?;
    println!("\nreleased");
    Ok(())
}

// ----------------------------------------------------------------------------------------
// A minimal server, so the example needs nothing to talk to.
//
// This is the same `Association` the client uses, in the server role: bytes in, bytes out,
// events out. Everything below the `answer` function is transport; everything inside it is
// the IEC 61850 model this pretends to have.
// ----------------------------------------------------------------------------------------

/// The data set the report control block reports, and its two members.
const MEMBERS: [&str; 2] = ["IED1LD0/PTRC1$ST$Tr$general", "IED1LD0/PTRC1$ST$Tr$q"];

struct Server {
    assoc: Association,
    /// The report control block, attribute by attribute — which is how a real one is
    /// addressed, and the only way that survives an edition difference.
    rcb: Vec<(&'static str, Value)>,
    seq: u32,
}

fn spawn_server() -> Result<String, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            serve(stream);
        }
    });
    Ok(addr)
}

fn serve(mut stream: TcpStream) {
    let mut s = Server {
        assoc: Association::server(AssociationConfig::default()),
        rcb: vec![
            ("RptID", Value::VisibleString(String::from(RCB))),
            ("RptEna", Value::Boolean(false)),
            ("DatSet", Value::VisibleString(String::from("IED1LD0/LLN0$dsTrip"))),
            ("ConfRev", Value::Unsigned(3)),
            ("OptFlds", OptFlds::NONE.to_value()),
            ("BufTm", Value::Unsigned(0)),
            ("SqNum", Value::Unsigned(0)),
            ("TrgOps", TrgOps::NONE.to_value()),
            ("IntgPd", Value::Unsigned(0)),
            ("GI", Value::Boolean(false)),
            ("Resv", Value::Boolean(false)),
        ],
        seq: 0,
    };
    let mut buf = [0u8; 4096];
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    loop {
        let received = match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.get(..n).unwrap_or(&[]).to_vec(),
        };
        s.assoc.on_bytes(Instant::ZERO, &received);
        let mut requests = Vec::new();
        while let Some(event) = s.assoc.poll_event() {
            match event {
                AssociationEvent::Request { invoke_id, pdu } => requests.push((invoke_id, pdu)),
                AssociationEvent::Closed(_) => return,
                _ => {}
            }
        }
        for (invoke_id, pdu) in requests {
            answer(&mut s, invoke_id, &pdu);
        }
        while let Some(packet) = s.assoc.poll_transmit() {
            let packet = packet.to_vec();
            if stream.write_all(&packet).is_err() {
                return;
            }
        }
    }
}

fn answer(s: &mut Server, invoke_id: i64, pdu: &[u8]) {
    let Ok(Mms::ConfirmedRequest { service, .. }) = Mms::parse(pdu, &Limits::DEFAULT) else { return };
    let _ = match service {
        ConfirmedRequest::Identify => s.assoc.respond(invoke_id, &ConfirmedResponse::Identify { vendor: "hupe1980", model: "iec61850-rs", revision: "0.1.0" }),
        ConfirmedRequest::GetNameList { object_class: class, scope, .. } => {
            let names: &[&str] = match (class, scope) {
                (object_class::DOMAIN, ObjectScope::VmdSpecific) => &[LD],
                (object_class::NAMED_VARIABLE, ObjectScope::DomainSpecific(LD)) => &["MMXU1$MX$TotW$mag$f", "PTRC1$ST$Tr$general", "CSWI1$CO$Pos$Oper"],
                (object_class::NAMED_VARIABLE_LIST, ObjectScope::DomainSpecific(LD)) => &["LLN0$dsTrip"],
                _ => &[],
            };
            s.assoc.respond(invoke_id, &ConfirmedResponse::GetNameList { identifiers: names.to_vec(), more_follows: false })
        }
        ConfirmedRequest::GetNamedVariableListAttributes(_) => s.assoc.respond(
            invoke_id,
            &ConfirmedResponse::GetNamedVariableListAttributes {
                deletable: false,
                variables: vec![VariableSpecification::Name(ObjectName::DomainSpecific { domain: LD, item: "PTRC1$ST$Tr$general" })],
            },
        ),
        ConfirmedRequest::Read { access, .. } => return read(s, invoke_id, &access),
        ConfirmedRequest::Write { access, values } => return write(s, invoke_id, &access, &values),
        _ => Ok(()),
    };
}

/// The MMS item of a domain-specific name.
fn item_of<'a>(spec: &VariableSpecification<'a>) -> Option<&'a str> {
    match spec {
        VariableSpecification::Name(ObjectName::DomainSpecific { item, .. }) => Some(item),
        _ => None,
    }
}

fn names_of(access: &VariableAccess<'_>) -> Vec<Option<String>> {
    match access {
        VariableAccess::ListOfVariable(v) => v.iter().map(|s| item_of(s).map(String::from)).collect(),
        VariableAccess::VariableListName(_) => vec![None],
    }
}

fn read(s: &mut Server, invoke_id: i64, access: &VariableAccess<'_>) {
    let values: Vec<Option<Value>> = names_of(access)
        .iter()
        .map(|name| match name.as_deref() {
            // A control block is read attribute by attribute; an attribute this edition does
            // not have simply is not there.
            Some(item) if item.starts_with("LLN0$RP$urcb01") => {
                let attribute = item.rsplit('$').next().unwrap_or("");
                s.rcb.iter().find(|(a, _)| *a == attribute).map(|(_, v)| v.clone())
            }
            // A select is granted by answering with the object reference.
            Some("CSWI1$CO$Pos$SBO") => Some(Value::VisibleString(format!("{LD}/CSWI1$CO$Pos"))),
            _ => Some(Value::Float32(12345.6)),
        })
        .collect();
    let encoded: Vec<Option<Vec<u8>>> = values.iter().map(|v| v.as_ref().map(|v| Value::encode_all(std::slice::from_ref(v)).unwrap_or_default())).collect();
    let results: Vec<AccessResult<'_>> = encoded
        .iter()
        .map(|b| match b.as_ref().and_then(|b| Cursor::new(b).next_required().ok()) {
            Some(tlv) => AccessResult::Success(tlv),
            // 10 is object-non-existent.
            None => AccessResult::Failure(10),
        })
        .collect();
    let _ = s.assoc.respond(invoke_id, &ConfirmedResponse::Read { access: None, results });
}

fn write(s: &mut Server, invoke_id: i64, access: &VariableAccess<'_>, values: &[iec61850_rs::ber::Tlv<'_>]) {
    let mut outcomes = Vec::new();
    let mut gi = false;
    let mut operated: Option<ControlRequest> = None;
    for (name, tlv) in names_of(access).iter().zip(values) {
        let Ok(value) = iec61850_rs::proto::data::DataView::from_tlv(*tlv).and_then(|d| d.to_owned(&Limits::DEFAULT)) else {
            outcomes.push(WriteResult::Failure(11));
            continue;
        };
        match name.as_deref() {
            Some(item) if item.starts_with("LLN0$RP$urcb01") => {
                let attribute = item.rsplit('$').next().unwrap_or("");
                let enabled = s.rcb.iter().find(|(a, _)| *a == "RptEna").and_then(|(_, v)| v.as_bool()).unwrap_or(false);
                if attribute == "GI" {
                    gi = true;
                    outcomes.push(WriteResult::Success);
                } else if enabled && attribute != "RptEna" {
                    // A server refuses every other write while reporting is on: 3 is
                    // object-access-denied.
                    outcomes.push(WriteResult::Failure(3));
                } else {
                    if let Some(slot) = s.rcb.iter_mut().find(|(a, _)| *a == attribute) {
                        slot.1 = value;
                    }
                    outcomes.push(WriteResult::Success);
                }
            }
            Some(item) if item.starts_with("CSWI1$CO$Pos") => {
                if item.ends_with("$Oper") {
                    operated = ControlRequest::from_value(&value).ok();
                }
                outcomes.push(WriteResult::Success);
            }
            _ => outcomes.push(WriteResult::Success),
        }
    }
    let _ = s.assoc.respond(invoke_id, &ConfirmedResponse::Write(outcomes));
    if gi {
        send_report(s, ReasonCode::NONE.with_general_interrogation(true));
    }
    if let Some(request) = operated {
        send_termination(s, &request);
    }
}

/// Build a report the way IEC 61850-8-1 Table 40 orders it, and send it.
fn send_report(s: &mut Server, reason: ReasonCode) {
    s.seq = s.seq.wrapping_add(1);
    let get = |a: &str| s.rcb.iter().find(|(n, _)| *n == a).map(|(_, v)| v.clone());
    let opt_flds = get("OptFlds").as_ref().and_then(OptFlds::from_value).unwrap_or(OptFlds::NONE);
    let report = Report {
        rpt_id: get("RptID").as_ref().and_then(|v| v.as_str().map(String::from)).unwrap_or_default(),
        opt_flds,
        seq_num: opt_flds.sequence_number().then_some(s.seq),
        time_of_entry: opt_flds.report_time_stamp().then(|| EntryTime::from_unix_millis(1_700_000_000_000)),
        data_set: opt_flds.data_set_name().then(|| String::from("IED1LD0/LLN0$dsTrip")),
        buf_ovfl: opt_flds.buffer_overflow().then_some(false),
        entry_id: opt_flds.entry_id().then(|| vec![0; 8]),
        conf_rev: opt_flds.conf_revision().then_some(3),
        sub_seq_num: None,
        more_segments_follow: false,
        inclusion: Report::inclusion_for(MEMBERS.len(), &[0, 1]),
        entries: vec![
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
        ],
    };
    let Ok(values) = report.to_values() else { return };
    send_information_report(s, VariableAccess::VariableListName(ObjectName::DomainSpecific { domain: LD, item: "LLN0$RP$urcb01" }), &values);
}

/// A positive command termination: the `Oper` variable alone, echoed back.
fn send_termination(s: &mut Server, request: &ControlRequest) {
    let names = vec![VariableSpecification::Name(ObjectName::DomainSpecific { domain: LD, item: "CSWI1$CO$Pos$Oper" })];
    // A *negative* one would put a `LastApplError` in front of it, carrying the `AddCause`.
    send_information_report(s, VariableAccess::ListOfVariable(names), &[request.to_value()]);
}

fn send_information_report(s: &mut Server, access: VariableAccess<'_>, values: &[Value]) {
    let encoded: Vec<Vec<u8>> = values.iter().map(|v| Value::encode_all(std::slice::from_ref(v)).unwrap_or_default()).collect();
    let Some(results) = encoded.iter().map(|b| Cursor::new(b).next_required().ok().map(AccessResult::Success)).collect::<Option<Vec<_>>>() else {
        return;
    };
    let _ = s.assoc.send(&Mms::Unconfirmed(Unconfirmed::InformationReport { access, results }));
}
