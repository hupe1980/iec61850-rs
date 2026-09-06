//! `ied` — one command-line tool for IEC 61850.
//!
//! Subcommands mirror the library: decode and inspect process-bus traffic, load, check and
//! resolve SCL files, and generate sampled values. One binary rather than a family of them,
//! because `ip`, `tc` and `cargo` are what users' hands already know.
//!
//! `goose sniff` and `sv monitor` drive the library's own subscriber state machines rather
//! than re-deciding anything, so what the tool reports about a frame is what a subscribing
//! IED would decide about it.
//!
//! Everything here works on capture files. Live capture arrives with the network adapters;
//! until then a pcap is the interface, which has the pleasant side effect that every
//! subcommand is testable in CI.

// Timestamps and rates are cast to `f64` only to be printed; the precision a `u64`
// nanosecond count loses past 2^52 is 104 days of sub-nanosecond digits nobody reads.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::cast_precision_loss)]

use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;

use iec61850_rs::client::{Client, ClientConfig, RcbSettings, Unsolicited};
use iec61850_rs::common::{Edition, EntryTime, Fc, Instant, Limits, TimeQuality, UtcTime};
use iec61850_rs::model::IedModel;
use iec61850_rs::pcap::{Capture, Writer};
use iec61850_rs::proto::data::{Typed, Value as IedValue};
use iec61850_rs::proto::ethernet::{ETHERTYPE_GOOSE, ETHERTYPE_GSE_MGMT, ETHERTYPE_SV, Frame, FrameHeader, MacAddr, VlanTag};
use iec61850_rs::proto::goose::{GoosePduView, Subscriber as GooseSubscriber, SubscriberConfig, SubscriberEvent, SubscriptionKey};
use iec61850_rs::proto::mms::control::{AddCause, Check, ControlModel, OriginCategory};
use iec61850_rs::proto::mms::file;
use iec61850_rs::proto::mms::report::{OptFlds, ReasonCode, Report, TrgOps};
use iec61850_rs::proto::mms::typespec::TypeSpec;
use iec61850_rs::proto::sv::le::PhsMeas1;
use iec61850_rs::proto::sv::{ChannelValue, Publisher, PublisherConfig, SavPduView, SmpMod, SmpSynch, StreamConfig, StreamKey, SvProfile};
use iec61850_rs::scl::{self, LoadOptions};
use iec61850_rs::server::{DirectoryStore, Ied, Server};

const USAGE: &str = "\
ied — IEC 61850 command line

USAGE:
    ied <COMMAND> [ARGS]

COMMANDS:
    goose sniff <FILE.pcap>        Decode GOOSE and run the subscriber's verdict over it
    mms sniff <FILE.pcap>          Decode MMS over the OSI stack: association, services, values
    mms identify <HOST[:PORT]>     Associate with a server and print what it says it is
    mms status <HOST[:PORT]>       Ask whether the server is healthy — the cheapest round trip there is
    mms browse <HOST[:PORT]>       Walk the server: logical devices, data, data sets
    mms read <HOST[:PORT]> <REF>   Read one data attribute
    mms write <HOST[:PORT]> <REF> <VALUE>
                                   Write one data attribute
    mms report <HOST[:PORT]>       Enable a report control block and print its reports
    mms rcb <HOST[:PORT]> <REF>    Print a report control block's configuration
    mms control <HOST[:PORT]> <REF> <VALUE>
                                   Operate a controllable object
    mms type <HOST[:PORT]> <REF>   What type a variable is, read from the server
    mms files <HOST[:PORT]> [DIR]  List the server's files
    mms get <HOST[:PORT]> <PATH> [OUT]
                                   Read a file off the server (COMTRADE records live here)
    mms log <HOST[:PORT]> <LOG>    Read a log's entries; --lcb prints its control block
    mms sg <HOST[:PORT]> [REF]     Setting groups: print, --activate N, --edit N
    sv monitor <FILE.pcap>         Track sampled-value streams: gaps, sync, staleness
    pcap info <FILE.pcap>          Summarise what a capture contains
    scl validate <FILE.scl>        Engineering checks the XML schema does not make
    scl show <FILE.scl> [IED]      Print an IED's model: devices, nodes, control blocks
    scl subs <FILE.scd> <IED>      What an IED subscribes to, resolved from the publishers
    mu <FILE.pcap> [OPTIONS]       Generate a sampled-value stream into a capture
    sim <FILE.scd|.icd|.cid>       Serve the file's IEDs as real MMS servers

`mms` client options (identify/browse/read/write/report):
    --fc <ST|MX|CO|SP|...>  functional constraint for a dotted reference. Reads default to
                            ST; `mms write` requires it, because a conforming server refuses
                            a write to ST and MX — those are what the process reports.
                            Settings are SP/SE, configuration CF, description DC.
    --password <TEXT>       ACSE password (IEC 61850-8-1 authentication)
    --type <bool|int|uint|float|string>
                            how to encode the value of `mms write` (default bool)
    --timeout <SECONDS>     how long to wait for an answer (default 30)
    --seconds <N>           how long `mms report` listens (default 30)
    --rcb <REF>             report control block for `mms report` to enable
    --buffered              the control block is buffered (BR); inferred from a $BR$ reference
    --data-set <REF>        data set to report, in MMS form (LD/LLN0$dsTrip)
    --intg-pd <MS>          integrity period; also turns the integrity trigger on
    --gi                    request a general interrogation after enabling
    --model <direct|sbo|direct-enhanced|sbo-enhanced>
                            control model of the object (default direct)
    --orcat <0-8>           originator category (default 3, remote control)
    --orident <TEXT>        originator identifier (default `ied`)
    --synchro, --interlock  ask the server to run these checks before operating
    --test                  mark the command as a test
    --max-size <BYTES>      largest file `mms get` will read (default 16777216)
    --activate <N>          `mms sg`: put setting group N into force
    --edit <N>              `mms sg`: reserve setting group N for editing
    --lcb <REF>             `mms log`: also read this log control block
    --entries <N>           `mms log`: stop after this many entries (default 1000)
    --scd <FILE> --ied <N>  take the OSI selectors and AP-title from the engineering file;
                            with a host of `-`, take the IP address from it too
    --local-tsel <HEX>      OSI transport selector this end presents (default 0001)
    --remote-tsel <HEX>     OSI transport selector of the server (default 0001)

`sim` options:
    --ied <NAME>        serve only this IED (default: every IED in the file)
    --bind <ADDR>       address to listen on (default 127.0.0.1)
    --port <N>          first port; each further IED takes the next one (default 102)
    --files <DIR>       serve this directory through the MMS file services, read-only
    --writable          also allow `FileDelete` on that directory
    --edition <1|2|2.1> serve as this edition, overriding the file's own schema version
                        (Edition 1 has no ResvTms and no Owner on a report control block)

`scl validate` options:
    --freq <50|60>      nominal frequency, to read smpRate (default 50)
    --edition <1|2|2.1> edition whose object-reference limit applies (default 2.1)
    --strict            treat warnings as errors

`scl subs` options:
    --freq <50|60>      nominal frequency, to read smpRate (default 50)

`sv monitor` options:
    --freq <50|60>      nominal frequency, to read smpRate in samples per period (default 50)
    --rate <N>          samples per second, overriding what the stream advertises
    --scd <FILE.scd>    configure the streams from an engineering file instead of from the
                        capture: rate, confRev and the data set that says what each ASDU's
                        octets mean, so samples decode into named channels
    --ied <NAME>        with --scd, only the streams this IED publishes

`mu` options:
    --profile <le80-50|le80-60|le256-50|le256-60|f4800s2|f14400s6>   default le80-50
    --frames <N>        frames to generate (default 1000)
    --sv-id <ID>        svID to publish (default MU01)
    --appid <HEX>       APPID (default 4000)
    --freq <N>          nominal frequency of the synthetic waveform in Hz (default 50)
    --amplitude <N>     peak of the synthetic sinusoid, raw units (default 100000)
    --gm <HEX>          publish gmIdentity, 8 octets as 16 hex digits
    --refr-tm           publish refrTm on every ASDU
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match words.as_slice() {
        [] | ["-h" | "--help" | "help"] => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        ["--version" | "-V"] => {
            println!("ied {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["goose", "sniff", file] => goose_sniff(file),
        ["mms", "sniff", file] => mms_sniff(file),
        ["mms", "identify", host, rest @ ..] => mms_identify(host, rest),
        ["mms", "status", host, rest @ ..] => mms_status(host, rest),
        ["mms", "browse", host, rest @ ..] => mms_browse(host, rest),
        ["mms", "read", host, reference, rest @ ..] => mms_read(host, reference, rest),
        ["mms", "write", host, reference, value, rest @ ..] => mms_write(host, reference, value, rest),
        ["mms", "report", host, rest @ ..] => mms_report(host, rest),
        ["mms", "rcb", host, reference, rest @ ..] => mms_rcb(host, reference, rest),
        ["mms", "control", host, reference, value, rest @ ..] => mms_control(host, reference, value, rest),
        ["mms", "type", host, reference, rest @ ..] => mms_type(host, reference, rest),
        ["mms", "files", host, rest @ ..] => mms_files(host, rest),
        ["mms", "get", host, path, rest @ ..] => mms_get(host, path, rest),
        ["mms", "log", host, log, rest @ ..] => mms_log(host, log, rest),
        ["mms", "sg", host, rest @ ..] => mms_setting_groups(host, rest),
        ["sv", "monitor", file, rest @ ..] => sv_monitor(file, rest),
        ["pcap", "info", file] => pcap_info(file),
        ["scl", "validate", file, rest @ ..] => scl_validate(file, rest),
        ["scl", "show", file, rest @ ..] => scl_show(file, rest.first().copied()),
        ["scl", "subs", file, ied, rest @ ..] => scl_subs(file, ied, rest),
        ["mu", file, rest @ ..] => merging_unit(file, rest),
        ["sim", file, rest @ ..] => simulate(file, rest),
        other => Err(format!("unknown command `{}`\n\n{USAGE}", other.join(" "))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ied: {e}");
            ExitCode::FAILURE
        }
    }
}

fn read(file: &str) -> Result<Capture, String> {
    Capture::read(file).map_err(|e| format!("{file}: {e}"))
}

fn goose_sniff(file: &str) -> Result<(), String> {
    let capture = read(file)?;

    // Pass one finds the streams; pass two runs the library's own subscriber over each of
    // them, so what the sniffer reports about a frame is what a subscribing IED would
    // decide about it — replays included.
    let mut keys: Vec<SubscriptionKey> = Vec::new();
    for (_, frame) in &capture.frames {
        let Ok(fr) = Frame::parse(frame) else { continue };
        if fr.ethertype != ETHERTYPE_GOOSE {
            continue;
        }
        let Ok(p) = GoosePduView::parse(fr.apdu) else { continue };
        if !keys.iter().any(|k| k.dst == fr.dst && k.appid == fr.appid && k.gocb_ref == p.gocb_ref) {
            keys.push(SubscriptionKey { dst: fr.dst, appid: fr.appid, gocb_ref: p.gocb_ref.to_string() });
        }
    }
    let mut subs: Vec<GooseSubscriber> = keys.iter().map(|k| GooseSubscriber::new(SubscriberConfig::new(k.clone()))).collect();

    let t0 = capture.frames.first().map_or(0, |(t, _)| *t);
    let mut n = 0u64;
    let mut malformed = 0u64;
    for (ts, frame) in &capture.frames {
        let Ok(fr) = Frame::parse(frame) else { continue };
        if fr.ethertype != ETHERTYPE_GOOSE {
            continue;
        }
        let at = (ts - t0) as f64 / 1e6;
        let Ok(p) = GoosePduView::parse(fr.apdu) else {
            malformed += 1;
            println!("{at:>10.3}ms malformed GOOSE");
            continue;
        };
        n += 1;
        let flags =
            [if p.simulation { "sim " } else { "" }, if p.nds_com { "ndsCom " } else { "" }, if p.member_count_matches() { "" } else { "COUNT-MISMATCH " }]
                .concat();
        println!(
            "{at:>10.3}ms {} appid={:#06x} stNum={} sqNum={} tal={}ms conf={} members={} {}t={}",
            p.gocb_ref, fr.appid, p.st_num, p.sq_num, p.time_allowed_to_live, p.conf_rev, p.num_dat_set_entries, flags, p.t
        );
        let Some(i) = keys.iter().position(|k| k.dst == fr.dst && k.appid == fr.appid && k.gocb_ref == p.gocb_ref) else { continue };
        let Some(sub) = subs.get_mut(i) else { continue };
        let now = Instant(ts - t0);
        sub.on_frame(now, frame);
        sub.on_timeout(now);
        while let Some(e) = sub.poll_event() {
            // A state change and a retransmission are already on the line above; what the
            // state machine adds is the verdict on everything else.
            if !matches!(e, SubscriberEvent::NewState { .. } | SubscriberEvent::Retransmission { .. }) {
                println!("{:>12} {e:?}", "!");
            }
        }
    }

    for (k, sub) in keys.iter().zip(&subs) {
        let s = sub.stats();
        println!("{} {} appid={:#06x}", k.dst, k.gocb_ref, k.appid);
        println!(
            "  accepted={} states={} retransmissions={} replays={} expiries={} malformed={} member-count={} sim-mismatch={}",
            s.accepted, s.state_changes, s.retransmissions, s.replays, s.expiries, s.malformed, s.member_count_mismatches, s.simulation_mismatches
        );
        if s.state_gaps > 0 {
            // States the publisher sent while this subscription was live and that never
            // arrived: a gap here is lost protection signalling, not a decoding detail.
            println!("  state gaps={} ({} state changes never arrived)", s.state_gaps, s.states_missed);
        }
        if let Some(d) = sub.deltas() {
            // The reduced feature set the GOOSE intrusion-detection literature selects,
            // computed by the subscriber on its way to a verdict rather than by a second
            // parser on a mirror port.
            println!(
                "  last deltas: stDiff={} sqDiff={} arrival={:.3}ms t={:.3}ms sinceChange={:.3}ms",
                d.st_diff,
                d.sq_diff,
                d.arrival_delta as f64 / 1e6,
                d.t_delta as f64 / 1e6,
                d.since_state_change as f64 / 1e6
            );
        }
    }
    println!("{n} GOOSE frames in {} stream(s){}", keys.len(), if malformed > 0 { format!(", {malformed} malformed") } else { String::new() });
    Ok(())
}

/// `ied mms sniff` — the whole OSI stack over a capture.
///
/// MMS does not run on TCP; it runs on ACSE over presentation over session over COTP over
/// TPKT over TCP. Printing what a capture holds means decoding all six, which is what makes
/// this a useful check on the stack as well as a useful tool.
fn mms_sniff(file: &str) -> Result<(), String> {
    use iec61850_rs::proto::osi::cotp::Tpdu;
    use iec61850_rs::proto::osi::presentation::Ppdu;
    use iec61850_rs::proto::osi::session::Spdu;
    use iec61850_rs::proto::osi::tpkt;

    let capture = read(file)?;
    let t0 = capture.frames.first().map_or(0, |(t, _)| *t);
    // One TPKT reader per direction: a header may arrive in a segment of its own.
    let (mut to_server, mut to_client) = (tpkt::Reader::new(), tpkt::Reader::new());
    let mut tally = MmsTally::default();
    let mut printed = 0u32;

    for (ts, frame) in &capture.frames {
        let Some((to_srv, payload)) = tcp_payload(frame) else { continue };
        let reader = if to_srv { &mut to_server } else { &mut to_client };
        reader.push(payload);
        loop {
            let tpdu = match reader.next_tpdu() {
                Ok(Some(t)) => t.to_vec(),
                Ok(None) => break,
                Err(e) => {
                    println!("  not a TPKT stream: {e}");
                    break;
                }
            };
            let at = (ts - t0) as f64 / 1e6;
            let arrow = if to_srv { "->" } else { "<-" };
            let Ok(cotp) = Tpdu::parse(&tpdu) else {
                tally.malformed += 1;
                continue;
            };
            let payload = match cotp {
                Tpdu::ConnectionRequest(c) => {
                    println!(
                        "{at:>10.3}ms {arrow} COTP CR src-ref={:#06x} tpdu-size={} tsel {:02x?}->{:02x?}",
                        c.src_ref,
                        c.max_data() + 3,
                        c.src_tsel.map(|t| t.0).unwrap_or_default(),
                        c.dst_tsel.map(|t| t.0).unwrap_or_default()
                    );
                    continue;
                }
                Tpdu::ConnectionConfirm(c) => {
                    println!("{at:>10.3}ms {arrow} COTP CC dst-ref={:#06x} tpdu-size={}", c.dst_ref, c.max_data() + 3);
                    continue;
                }
                Tpdu::Data { payload, .. } => payload,
                other => {
                    println!("{at:>10.3}ms {arrow} COTP {other:?}");
                    continue;
                }
            };
            let Ok(spdu) = Spdu::parse(payload) else {
                tally.malformed += 1;
                continue;
            };
            let (bytes, handshake) = match spdu {
                Spdu::Connect(ref c) | Spdu::Accept(ref c) => (c.user_data, true),
                Spdu::DataTransfer(p) => (p, false),
                other => {
                    println!("{at:>10.3}ms {arrow} session {other:?}");
                    continue;
                }
            };
            let Ok(ppdu) = Ppdu::parse(bytes, handshake) else {
                tally.malformed += 1;
                continue;
            };
            let pdvs = match &ppdu {
                Ppdu::Reject(cp) => {
                    println!("{at:>10.3}ms {arrow} CPR presentation connection REFUSED, provider reason {:?}", cp.provider_reason);
                    cp.user_data.clone()
                }
                Ppdu::Connect(cp) | Ppdu::Accept(cp) => {
                    let what = if matches!(ppdu, Ppdu::Connect(_)) { "CP " } else { "CPA" };
                    let contexts: Vec<String> = cp.contexts.iter().map(|c| format!("{}={}", c.id, c.abstract_syntax)).collect();
                    if contexts.is_empty() {
                        println!("{at:>10.3}ms {arrow} {what} {} context result(s), all accepted: {}", cp.results.len(), cp.all_accepted());
                    } else {
                        println!("{at:>10.3}ms {arrow} {what} contexts {}", contexts.join(" "));
                    }
                    cp.user_data.clone()
                }
                Ppdu::UserData(p) => p.clone(),
            };
            for pdv in pdvs {
                let Some(value) = pdv.values.single() else { continue };
                print_pdv(at, arrow, pdv.context_id, value, &mut tally, &mut printed);
            }
        }
    }
    println!("{} request(s), {} response(s), {} report(s), {} value(s)", tally.requests, tally.responses, tally.reports, tally.values);
    if tally.iec_reports > 0 || tally.terminations > 0 {
        println!("  of those, {} IEC 61850 report(s) and {} command termination(s)", tally.iec_reports, tally.terminations);
    }
    if tally.malformed > 0 {
        println!("{} PDU(s) did not decode", tally.malformed);
    }
    Ok(())
}

/// What `ied mms sniff` counted.
#[derive(Default)]
struct MmsTally {
    requests: u64,
    responses: u64,
    reports: u64,
    /// Reports that decode as IEC 61850 reports rather than as a bare data-set report.
    iec_reports: u64,
    terminations: u64,
    values: usize,
    malformed: u64,
}

/// Print one presentation data value: an ACSE APDU in context 1, an MMS PDU anywhere else.
fn print_pdv(at: f64, arrow: &str, context_id: u16, value: &[u8], tally: &mut MmsTally, printed: &mut u32) {
    use iec61850_rs::proto::mms::{ConfirmedResponse, Mms, ObjectName, Unconfirmed, VariableAccess};
    use iec61850_rs::proto::osi::Oid;
    use iec61850_rs::proto::osi::acse::Apdu;

    let mms = if context_id == 1 {
        match Apdu::parse(value) {
            Ok(Apdu::Associate(a)) => {
                let auth = if a.mechanism_name == Some(Oid::PASSWORD_MECHANISM) { " (ACSE password)" } else { "" };
                println!("{at:>10.3}ms {arrow} AARQ context {}{auth}", a.context_name.map_or_else(String::new, |o| o.to_string()));
                a.mms_pdu()
            }
            Ok(Apdu::AssociateResponse(a)) => {
                println!("{at:>10.3}ms {arrow} AARE {}", if a.accepted() { "accepted" } else { "REJECTED" });
                a.mms_pdu()
            }
            Ok(other) => {
                println!("{at:>10.3}ms {arrow} ACSE {other:?}");
                None
            }
            Err(_) => {
                tally.malformed += 1;
                None
            }
        }
    } else {
        Some(value)
    };
    let Some(bytes) = mms else { return };
    let Ok(pdu) = Mms::parse(bytes, &Limits::DEFAULT) else {
        tally.malformed += 1;
        return;
    };
    let line = match &pdu {
        Mms::InitiateRequest(i) | Mms::InitiateResponse(i) => format!(
            "Initiate maxPDU={:?} outstanding {}/{} nesting {:?} version {}",
            i.local_detail, i.max_serv_outstanding_calling, i.max_serv_outstanding_called, i.data_structure_nesting_level, i.version
        ),
        Mms::ConfirmedRequest { invoke_id, service } => {
            tally.requests += 1;
            format!("invoke {invoke_id} {}", describe_request(service))
        }
        Mms::ConfirmedResponse { invoke_id, service } => {
            tally.responses += 1;
            if let ConfirmedResponse::Read { results, .. } = service {
                tally.values += results.len();
            }
            format!("invoke {invoke_id} {}", describe_response(service))
        }
        Mms::ConfirmedError { invoke_id, .. } => format!("invoke {invoke_id} ERROR"),
        Mms::Unconfirmed(Unconfirmed::InformationReport { access, results }) => {
            tally.reports += 1;
            tally.values += results.len();
            let name = match access {
                VariableAccess::VariableListName(ObjectName::DomainSpecific { domain, item }) => format!("{domain}/{item}"),
                VariableAccess::VariableListName(n) => object_name(n),
                VariableAccess::ListOfVariable(v) => format!("{} variable(s)", v.len()),
            };
            // An unconfirmed PDU is one of three things and the tool says which, using the
            // same classifier a client uses — so what it reports is what a client would see.
            match Unsolicited::from_pdu(bytes, &Limits::DEFAULT) {
                Some(Unsolicited::Report(r)) => {
                    tally.iec_reports += 1;
                    format!(
                        "report {} sq={} {} of {} members{}",
                        r.rpt_id,
                        r.seq_num.map_or_else(|| String::from("-"), |n| n.to_string()),
                        r.entries.len(),
                        r.data_set_len(),
                        if r.is_partial() { " (more segments follow)" } else { "" }
                    )
                }
                Some(Unsolicited::CommandTermination(t)) => {
                    tally.terminations += 1;
                    format!("command termination {} {}", if t.is_positive() { "+" } else { "-" }, t.control_object())
                }
                _ => format!("report {name} ({} values)", results.len()),
            }
        }
        other => format!("{other:?}"),
    };
    // Reports repeat; the first twenty lines are enough to see the shape.
    if *printed < 20 || !matches!(pdu, Mms::Unconfirmed(_)) {
        println!("{at:>10.3}ms {arrow} {line}");
        *printed += 1;
    }
}

/// One line for a confirmed request.
fn describe_request(service: &iec61850_rs::proto::mms::ConfirmedRequest<'_>) -> String {
    use iec61850_rs::proto::mms::{ConfirmedRequest, VariableAccess};
    match service {
        ConfirmedRequest::Identify => "identify".to_string(),
        ConfirmedRequest::Status { extended_derivation } => format!("status{}", if *extended_derivation { " (extended derivation)" } else { "" }),
        ConfirmedRequest::GetCapabilityList { .. } => String::from("getCapabilityList"),
        ConfirmedRequest::GetNameList { object_class, .. } => format!("getNameList class {object_class}"),
        ConfirmedRequest::Read { access, .. } => match access {
            VariableAccess::VariableListName(n) => format!("read {}", object_name(n)),
            VariableAccess::ListOfVariable(v) => {
                format!("read {}", v.first().map_or_else(|| format!("{} variables", v.len()), |s| variable(s, v.len())))
            }
        },
        ConfirmedRequest::Write { access, values } => match access {
            VariableAccess::VariableListName(n) => format!("write {} ({} values)", object_name(n), values.len()),
            VariableAccess::ListOfVariable(v) => format!("write {}", v.first().map_or_else(String::new, |s| variable(s, v.len()))),
        },
        ConfirmedRequest::GetNamedVariableListAttributes(n) => format!("getNamedVariableListAttributes {}", object_name(n)),
        ConfirmedRequest::GetVariableAccessAttributes(n) => format!("getVariableAccessAttributes {}", object_name(n)),
        ConfirmedRequest::DefineNamedVariableList { name, variables } => format!("defineNamedVariableList {} ({} members)", object_name(name), variables.len()),
        ConfirmedRequest::DeleteNamedVariableList { names, .. } => format!("deleteNamedVariableList ({} name(s))", names.len()),
        ConfirmedRequest::ReadJournal(r) => format!("readJournal {}", r.name.as_ref().map_or_else(String::new, object_name)),
        ConfirmedRequest::FileOpen { name, position } => format!("fileOpen {} at {position}", name.display()),
        ConfirmedRequest::FileRead(id) => format!("fileRead frsm {id}"),
        ConfirmedRequest::FileClose(id) => format!("fileClose frsm {id}"),
        ConfirmedRequest::FileDelete(name) => format!("fileDelete {}", name.display()),
        ConfirmedRequest::FileDirectory { specification, .. } => {
            format!("fileDirectory {}", specification.as_ref().map_or_else(|| String::from("*"), file::FileName::display))
        }
        ConfirmedRequest::Other(t) => format!("service [{}]", t.tag.number),
    }
}

/// One line for a confirmed response.
fn describe_response(service: &iec61850_rs::proto::mms::ConfirmedResponse<'_>) -> String {
    use iec61850_rs::proto::mms::ConfirmedResponse;
    match service {
        ConfirmedResponse::Identify { vendor, model, revision } => format!("identify {vendor} {model} {revision}"),
        ConfirmedResponse::Status { logical, physical, .. } => format!("status logical={logical} physical={physical}"),
        ConfirmedResponse::GetCapabilityList { capabilities, more_follows } => {
            format!("getCapabilityList {} capabilit(y|ies){}", capabilities.len(), if *more_follows { ", more follow" } else { "" })
        }
        ConfirmedResponse::GetNameList { identifiers, more_follows } => {
            format!("getNameList {} name(s){}", identifiers.len(), if *more_follows { ", more follow" } else { "" })
        }
        ConfirmedResponse::Read { results, .. } => format!("read {} value(s)", results.len()),
        ConfirmedResponse::Write(results) => format!("write {} result(s)", results.len()),
        ConfirmedResponse::GetNamedVariableListAttributes { variables, .. } => format!("data set of {} member(s)", variables.len()),
        ConfirmedResponse::GetVariableAccessAttributes { type_spec, .. } => format!("type {}", describe_type(type_spec)),
        ConfirmedResponse::DefineNamedVariableList => String::from("data set created"),
        ConfirmedResponse::DeleteNamedVariableList { matched, deleted } => format!("deleted {deleted} of {matched} matched"),
        ConfirmedResponse::ReadJournal { entries, more_follows } => {
            format!("{} log entr(y|ies){}", entries.len(), if *more_follows { ", more follow" } else { "" })
        }
        ConfirmedResponse::FileOpen { frsm_id, attributes } => format!("fileOpen frsm {frsm_id}, {} octets", attributes.size),
        ConfirmedResponse::FileRead { data, more_follows } => format!("{} octets{}", data.len(), if *more_follows { ", more follow" } else { "" }),
        ConfirmedResponse::FileClose => String::from("fileClose"),
        ConfirmedResponse::FileDelete => String::from("fileDelete"),
        ConfirmedResponse::FileDirectory { entries, more_follows } => {
            format!("{} file(s){}", entries.len(), if *more_follows { ", more follow" } else { "" })
        }
        ConfirmedResponse::Other(t) => format!("service [{}]", t.tag.number),
    }
}

/// A one-line shape for a type specification, for `ied mms sniff` and `ied mms type`.
fn describe_type(t: &TypeSpec) -> String {
    match t {
        TypeSpec::Structure { components, .. } => {
            format!("struct {{{}}}", components.iter().map(|c| c.name.clone().unwrap_or_default()).collect::<Vec<_>>().join(", "))
        }
        TypeSpec::Array { elements, element_type, .. } => format!("array[{elements}] of {}", describe_type(element_type)),
        TypeSpec::Boolean => String::from("BOOLEAN"),
        TypeSpec::BitString(n) => format!("BIT STRING({n})"),
        TypeSpec::Integer(w) => format!("INT{w}"),
        TypeSpec::Unsigned(w) => format!("INT{w}U"),
        TypeSpec::FloatingPoint { format_width, .. } => format!("FLOAT{format_width}"),
        TypeSpec::OctetString(n) => format!("OCTET STRING({n})"),
        TypeSpec::VisibleString(n) => format!("VisString({n})"),
        TypeSpec::MmsString(n) => format!("MMSString({n})"),
        TypeSpec::UtcTime => String::from("Timestamp"),
        TypeSpec::BinaryTime(dated) => String::from(if *dated { "EntryTime" } else { "TimeOfDay" }),
        TypeSpec::GeneralizedTime => String::from("GeneralizedTime"),
        TypeSpec::Bcd(n) => format!("BCD({n})"),
        TypeSpec::Named { domain, item } => domain.as_ref().map_or_else(|| item.clone(), |d| format!("{d}/{item}")),
        other => format!("{other:?}"),
    }
}

fn object_name(n: &iec61850_rs::proto::mms::ObjectName<'_>) -> String {
    use iec61850_rs::proto::mms::ObjectName;
    match n {
        ObjectName::DomainSpecific { domain, item } => format!("{domain}/{item}"),
        ObjectName::VmdSpecific(s) | ObjectName::AaSpecific(s) => (*s).to_string(),
    }
}

fn variable(s: &iec61850_rs::proto::mms::VariableSpecification<'_>, total: usize) -> String {
    use iec61850_rs::proto::mms::VariableSpecification;
    let more = if total > 1 { format!(" (+{} more)", total - 1) } else { String::new() };
    match s {
        VariableSpecification::Name(n) => format!("{}{more}", object_name(n)),
        // A selection is shown in IEC 61850's own reference syntax, so a sniffed read of one
        // array element does not print as a read of the whole array.
        VariableSpecification::Element { name, access } => format!("{}{access}{more}", object_name(name)),
        VariableSpecification::Other(_) => format!("{total} variable(s)"),
    }
}

/// The TCP payload of an Ethernet frame, and whether it is going to port 102.
///
/// The IP total length is what bounds the payload: a bare ACK is padded to the 60-octet
/// Ethernet minimum, and reading that padding as data would put six zero octets into a TPKT
/// reader.
fn tcp_payload(frame: &[u8]) -> Option<(bool, &[u8])> {
    if frame.len() < 34 || u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]) != 0x0800 || *frame.get(23)? != 6 {
        return None;
    }
    let ip_end = 14 + usize::from(u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]));
    let tcp = 14 + usize::from(frame.get(14)? & 0x0F) * 4;
    let data_off = usize::from(frame.get(tcp + 12)? >> 4) * 4;
    let payload = frame.get(tcp + data_off..ip_end.min(frame.len()))?;
    if payload.is_empty() {
        return None;
    }
    let dst_port = u16::from_be_bytes([*frame.get(tcp + 2)?, *frame.get(tcp + 3)?]);
    Some((dst_port == 102, payload))
}

/// `mms type` — what a variable is, straight from the server.
fn mms_type(host: &str, reference: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;
    let spec = c.variable_type(reference, o.fc).map_err(|e| format!("{reference}: {e}"))?;
    print_type(&spec, 0);
    let _ = c.release();
    Ok(())
}

/// Print a type specification as an indented tree — the shape a caller has to match.
fn print_type(spec: &TypeSpec, depth: usize) {
    let pad = "  ".repeat(depth);
    match spec {
        TypeSpec::Structure { components, .. } => {
            println!("{pad}struct");
            for c in components {
                let name = c.name.as_deref().unwrap_or("(unnamed)");
                match &c.type_spec {
                    TypeSpec::Structure { .. } | TypeSpec::Array { .. } => {
                        println!("{pad}  {name}");
                        print_type(&c.type_spec, depth + 2);
                    }
                    other => println!("{pad}  {name:<12} {}", describe_type(other)),
                }
            }
        }
        TypeSpec::Array { elements, element_type, .. } => {
            println!("{pad}array[{elements}]");
            print_type(element_type, depth + 1);
        }
        other => println!("{pad}{}", describe_type(other)),
    }
}

/// `mms files` — what the server has, and how big.
fn mms_files(host: &str, args: &[&str]) -> Result<(), String> {
    // A leading non-flag argument is the directory to list.
    let (dir, rest) = split_leading(args);
    let o = mms_options(rest)?;
    let mut c = mms_connect(host, &o)?;
    let files = c.file_directory(dir).map_err(|e| e.to_string())?;
    for f in &files {
        println!("{:>12}  {}  {}", f.size, f.last_modified.as_deref().unwrap_or("                "), f.name);
    }
    println!("{} file(s)", files.len());
    let _ = c.release();
    Ok(())
}

/// `mms get` — pull a file off the server, to a path or to stdout.
fn mms_get(host: &str, path: &str, args: &[&str]) -> Result<(), String> {
    let (out, rest) = split_leading(args);
    let o = mms_options(rest)?;
    let mut c = mms_connect(host, &o)?;
    let data = c.read_file(path, o.max_size).map_err(|e| format!("{path}: {e}"))?;
    if let Some(file) = out {
        std::fs::write(file, &data).map_err(|e| format!("{file}: {e}"))?;
        println!("{} octets -> {file}", data.len());
    } else {
        use std::io::Write as _;
        std::io::stdout().write_all(&data).map_err(|e| e.to_string())?;
    }
    let _ = c.release();
    Ok(())
}

/// `mms log` — a log's entries, oldest first, and optionally its control block.
fn mms_log(host: &str, log: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;
    let mut from = EntryTime::default();
    if let Some(reference) = &o.lcb {
        let lcb = c.read_lcb(reference, Fc::LG).map_err(|e| format!("{reference}: {e}"))?;
        println!("{}  {}", lcb.reference, if lcb.log_ena { "enabled" } else { "disabled" });
        println!("  LogRef  {}", lcb.log_ref.as_deref().unwrap_or("(none)"));
        println!("  DatSet  {}", lcb.data_set.as_deref().unwrap_or("(none)"));
        println!("  TrgOps  {}", describe_trg_ops(lcb.trg_ops));
        if let Some((_, oldest)) = lcb.oldest() {
            println!("  oldest  {oldest}");
            from = oldest;
        }
        if let Some(newest) = lcb.new_entry_time {
            println!("  newest  {newest}");
        }
    }
    let entries = c.read_whole_log(log, from, o.entries).map_err(|e| format!("{log}: {e}"))?;
    for e in &entries {
        let mut id = String::with_capacity(e.entry_id.len() * 2);
        for b in &e.entry_id {
            let _ = write!(id, "{b:02x}");
        }
        if let Some(text) = &e.annotation {
            println!("{} {id}  {text}", e.occurred);
        } else {
            match e.reason {
                Some(reason) => println!("{} {id}  {reason:?}", e.occurred),
                None => println!("{} {id}", e.occurred),
            }
            for (name, value) in &e.variables {
                println!("    {name} = {}", show_value(value));
            }
        }
    }
    println!("{} entr(y|ies)", entries.len());
    let _ = c.release();
    Ok(())
}

/// `mms sg` — the setting group control block, and the two things you do to it.
fn mms_setting_groups(host: &str, args: &[&str]) -> Result<(), String> {
    let (reference, rest) = split_leading(args);
    let o = mms_options(rest)?;
    let mut c = mms_connect(host, &o)?;
    // With no reference, take the first logical device the server has: an SGCB lives in LLN0.
    let reference = if let Some(r) = reference {
        String::from(r)
    } else {
        let ld = c.server_directory().map_err(|e| e.to_string())?;
        let first = ld.first().ok_or_else(|| String::from("the server has no logical device"))?;
        format!("{first}/LLN0$SP$SGCB")
    };
    if let Some(group) = o.edit {
        c.select_edit_setting_group(&reference, group).map_err(|e| format!("{reference}: {e}"))?;
        println!("editing group {group}");
    }
    if let Some(group) = o.activate {
        c.select_active_setting_group(&reference, group).map_err(|e| format!("{reference}: {e}"))?;
        println!("group {group} activated");
    }
    let sgcb = c.read_sgcb(&reference).map_err(|e| format!("{reference}: {e}"))?;
    println!("{}", sgcb.reference);
    println!("  NumOfSG {}", sgcb.num_of_sg.map_or_else(|| String::from("-"), |n| n.to_string()));
    println!("  ActSG   {}", sgcb.act_sg.map_or_else(|| String::from("-"), |n| n.to_string()));
    println!("  EditSG  {}", sgcb.edit_sg.map_or_else(|| String::from("-"), |n| n.to_string()));
    println!("  CnfEdit {}", sgcb.cnf_edit.map_or_else(|| String::from("-"), |b| b.to_string()));
    if let Some(t) = sgcb.last_activation {
        println!("  LActTm  {t}");
    }
    let _ = c.release();
    Ok(())
}

/// Split off a leading positional argument (anything that is not a `--flag`).
/// `sim` — serve an engineering file's IEDs as real MMS servers.
///
/// This is the shape the whole design points at: the SCL file *is* the configuration, so a
/// simulator is the file plus a socket and nothing else — no generated model, no build step,
/// no second description of the same IED to keep in step with the first.
fn simulate(file: &str, args: &[&str]) -> Result<(), String> {
    let mut o = SimOptions::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value"));
        match *arg {
            "--ied" => o.ied = Some(value()?.to_string()),
            "--bind" => o.bind = value()?.to_string(),
            "--port" => o.port = value()?.parse().map_err(|_| "--port needs a number".to_string())?,
            "--files" => o.files = Some(value()?.to_string()),
            "--writable" => o.writable = true,
            "--edition" => o.edition = Some(parse_edition(value()?)?),
            other => return Err(format!("unknown option `{other}`")),
        }
    }

    let xml = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let scl = scl::Scl::parse(&xml).map_err(|e| format!("{file}: {e}"))?;
    let names: Vec<String> = match &o.ied {
        Some(name) => vec![name.clone()],
        None => scl.ied_names(),
    };
    if names.is_empty() {
        return Err(format!("{file}: no IED to serve"));
    }

    let mut servers = Vec::new();
    for (n, name) in names.iter().enumerate() {
        let model = scl.model(Some(name)).map_err(|e| format!("{name}: {e}"))?;
        // A file the loader had to work around still serves; saying so is the point of the
        // diagnostics, and refusing would make `sim` useless on the files that need it most.
        for d in &model.diagnostics {
            eprintln!("ied: {name}: {d}");
        }
        let ied = match o.edition {
            Some(e) => Ied::with_edition(model, e),
            None => Ied::new(model),
        }
        .map_err(|e| format!("{name}: {e}"))?;
        let edition = ied.edition();
        let devices = ied.domain_names();
        // A file that engineers service tracking is unusual enough to be worth saying so:
        // otherwise the objects are just four more names in a browse.
        let trackers = iec61850_rs::server::Tracking::new(&ied).references();
        // Runs out at 65535 rather than wrapping onto a port already in use.
        let port = u16::try_from(n).ok().and_then(|n| o.port.checked_add(n)).ok_or_else(|| format!("{} IEDs do not fit above port {}", names.len(), o.port))?;
        let mut server = Server::bind(&format!("{}:{port}", o.bind), ied).map_err(|e| format!("{name}: {e}"))?;
        if let Some(dir) = &o.files {
            let store = DirectoryStore::new(dir);
            server.set_file_store(Box::new(if o.writable { store.writable() } else { store }));
        }
        let addr = server.local_addr().map_err(|e| e.to_string())?;
        println!("{name} on {addr} — {} — logical device(s) {}", edition_name(edition), devices.join(", "));
        if !trackers.is_empty() {
            println!("  service tracking: {}", trackers.join(", "));
        }
        servers.push(server);
    }
    if let Some(dir) = &o.files {
        println!("files from {dir}{}", if o.writable { " (deletable)" } else { " (read-only)" });
    }
    println!("serving; ^C to stop");

    // One accept thread per server, and this thread parks: a simulator that exits when its
    // first client disconnects is not a simulator.
    let mut handles = Vec::new();
    for server in servers {
        handles.push(std::thread::spawn(move || server.run()));
    }
    for h in handles {
        if let Ok(Err(e)) = h.join() {
            return Err(e.to_string());
        }
    }
    Ok(())
}

#[derive(Debug)]
struct SimOptions {
    ied: Option<String>,
    bind: String,
    port: u16,
    files: Option<String>,
    writable: bool,
    /// `None` takes the edition from the file, which is where an IED's edition is declared.
    edition: Option<Edition>,
}

impl Default for SimOptions {
    fn default() -> SimOptions {
        // Loopback and port 102: the standard port needs privileges, and a simulator that
        // binds every interface by default is a simulator someone finds on a substation LAN.
        SimOptions { ied: None, bind: String::from("127.0.0.1"), port: 102, files: None, writable: false, edition: None }
    }
}

fn split_leading<'a>(args: &'a [&'a str]) -> (Option<&'a str>, &'a [&'a str]) {
    if let Some((first, rest)) = args.split_first() {
        if !first.starts_with("--") {
            return (Some(*first), rest);
        }
    }
    (None, args)
}

fn sv_monitor(file: &str, args: &[&str]) -> Result<(), String> {
    let mut freq = 50u32;
    let mut rate: Option<u32> = None;
    let mut scd: Option<&str> = None;
    let mut ied: Option<&str> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value"));
        match *arg {
            "--freq" => freq = value()?.parse().map_err(|_| "--freq needs a number".to_string())?,
            "--rate" => rate = Some(value()?.parse().map_err(|_| "--rate needs a number".to_string())?),
            "--scd" => scd = Some(value()?),
            "--ied" => ied = Some(value()?),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if ied.is_some() && scd.is_none() {
        return Err(String::from("--ied only means something with --scd"));
    }
    if let Some(path) = scd {
        return sv_monitor_from_scl(file, path, ied, freq);
    }
    let capture = read(file)?;
    let found = discover_streams(&capture);
    if found.is_empty() {
        println!("no sampled values in {file}");
        return Ok(());
    }

    let configs: Vec<StreamConfig> = found
        .iter()
        .map(|d| {
            let per_second = rate.unwrap_or_else(|| d.samples_per_second(freq));
            StreamConfig::new(d.key.clone()).with_samples_per_second(per_second).with_stale_after_ms(1000)
        })
        .collect();
    let wraps: Vec<(u32, &str)> = configs
        .iter()
        .zip(&found)
        .map(|(c, d)| {
            (
                c.samples_per_second,
                if rate.is_some() {
                    "given"
                } else if c.samples_per_second == u32::from(d.max_smp_cnt) + 1 && d.smp_rate.is_none() {
                    "observed"
                } else {
                    "smpRate"
                },
            )
        })
        .collect();

    // Pass two is the library's own state machine: what the tool reports is exactly what a
    // subscribing IED would see, not a second implementation of the same checks.
    let mut sub = iec61850_rs::proto::sv::Subscriber::new(configs).with_event_capacity(4096);
    let t0 = capture.frames.first().map_or(0, |(t, _)| *t);
    let mut events: Vec<String> = Vec::new();
    for (ts, frame) in &capture.frames {
        let now = Instant(ts.saturating_sub(t0));
        sub.on_frame(now, frame, |_| {});
        while let Some(e) = sub.poll_event() {
            if events.len() < 20 {
                events.push(format!("  {:>10.3}ms {e:?}", (ts - t0) as f64 / 1e6));
            }
        }
    }

    for (i, d) in found.iter().enumerate() {
        let Some(st) = sub.state(i) else { continue };
        let per_frame = st.asdus.checked_div(st.frames).unwrap_or(0);
        let (wrap, source) = wraps.get(i).copied().unwrap_or((0, "?"));
        println!("svID={} appid={:#06x} dst={} confRev={} smpCnt wraps at {wrap} ({source})", d.key.sv_id, d.key.appid, d.key.dst, d.conf_rev);
        println!(
            "  frames={} asdus={} ({per_frame}/frame) last smpCnt={:?} smpSynch={:?} gaps={} samples lost={}",
            st.frames, st.asdus, st.last_smp_cnt, st.smp_synch, st.gaps, st.samples_lost
        );
        if let Some(gm) = st.gm_identity {
            println!("  grandmaster={}", gm.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().concat());
        }
    }
    if !events.is_empty() {
        println!("events:");
        for e in &events {
            println!("{e}");
        }
    }
    if sub.malformed() > 0 {
        println!("{} malformed frames", sub.malformed());
    }
    if sub.events_dropped() > 0 {
        println!("{} further events not shown", sub.events_dropped());
    }
    Ok(())
}

/// `sv monitor --scd`: the engineering file configures the streams, so every ASDU decodes
/// into the channels the data set declares instead of into an opaque block of octets.
///
/// This is the difference between a tool that can read 9-2LE and one that can read the
/// stream a merging unit was actually engineered to send.
fn sv_monitor_from_scl(capture_file: &str, scl_file: &str, ied: Option<&str>, freq: u32) -> Result<(), String> {
    let xml = std::fs::read_to_string(scl_file).map_err(|e| format!("{scl_file}: {e}"))?;
    let scl = scl::Scl::parse(&xml).map_err(|e| e.to_string())?;
    let names: Vec<String> = match ied {
        Some(n) => vec![n.to_string()],
        None => scl.ied_names(),
    };

    // Every addressed sampled-value control block in the file, as a subscriber configuration.
    let mut labels: Vec<String> = Vec::new();
    let mut configs: Vec<StreamConfig> = Vec::new();
    for name in &names {
        let model = scl.model(Some(name)).map_err(|e| format!("{name}: {e}"))?;
        for ld in &model.logical_devices {
            for ln in &ld.logical_nodes {
                for cb in &ln.smv_controls {
                    let reference = format!("{}/{}.{}", ld.name, ln.name, cb.name);
                    match model.sv_stream_config(&reference, freq) {
                        Ok(cfg) => {
                            labels.push(format!("{name} {reference}"));
                            configs.push(cfg.with_stale_after_ms(1000));
                        }
                        // A control block with no Communication address publishes nowhere:
                        // that is a finding for `scl validate`, not a failure here.
                        Err(e) => println!("skipping {reference}: {e}"),
                    }
                }
            }
        }
    }
    if configs.is_empty() {
        return Err(format!("{scl_file} configures no addressed sampled-value stream"));
    }

    let capture = read(capture_file)?;
    let n = configs.len();
    let mut sub = iec61850_rs::proto::sv::Subscriber::new(configs).with_event_capacity(4096);
    // The last sample block of each stream, copied out so it can be decoded for printing
    // once the run is over. The buffers are reused, so the capture pass does not grow.
    let mut last: Vec<(u16, Vec<u8>)> = vec![(0, Vec::new()); n];
    let t0 = capture.frames.first().map_or(0, |(t, _)| *t);
    let mut events: Vec<String> = Vec::new();
    for (ts, frame) in &capture.frames {
        let now = Instant(ts.saturating_sub(t0));
        sub.on_frame(now, frame, |s| {
            if let Some(slot) = last.get_mut(s.stream) {
                slot.0 = s.asdu.smp_cnt;
                slot.1.clear();
                slot.1.extend_from_slice(s.asdu.sample);
            }
        });
        while let Some(e) = sub.poll_event() {
            if events.len() < 20 {
                events.push(format!("  {:>10.3}ms {e:?}", (ts - t0) as f64 / 1e6));
            }
        }
    }

    for i in 0..n {
        let (Some(cfg), Some(st), Some(label)) = (sub.stream_config(i), sub.state(i), labels.get(i)) else { continue };
        println!("{label}");
        println!(
            "  svID={} appid={:#06x} dst={} smpCnt wraps at {} frames={} asdus={} gaps={} samples lost={}",
            cfg.key.sv_id, cfg.key.appid, cfg.key.dst, cfg.samples_per_second, st.frames, st.asdus, st.gaps, st.samples_lost
        );
        let Some(layout) = cfg.layout.as_ref() else {
            println!("  no fixed-width data set in the file: samples stay octets");
            continue;
        };
        println!("  {} channels, {} octets per ASDU", layout.channels().len(), layout.len());
        let Some((cnt, sample)) = last.get(i).filter(|(_, s)| !s.is_empty()) else {
            println!("  no sample of this stream in the capture");
            continue;
        };
        println!("  last sample (smpCnt={cnt}):");
        for (c, v) in layout.decode(sample) {
            println!("    {:<40} {}", c.name, show(v));
        }
    }
    if !events.is_empty() {
        println!("events:");
        for e in &events {
            println!("{e}");
        }
    }
    if sub.malformed() > 0 {
        println!("{} malformed frames", sub.malformed());
    }
    Ok(())
}

/// One channel value, printed the way an engineer reads it.
fn show(v: ChannelValue) -> String {
    match v {
        ChannelValue::Boolean(b) => b.to_string(),
        ChannelValue::Int(i) => i.to_string(),
        ChannelValue::Unsigned(u) => u.to_string(),
        ChannelValue::Float(f) => format!("{f}"),
        ChannelValue::Quality(q) => {
            if q.is_good() {
                String::from("good")
            } else {
                format!("{q:?}")
            }
        }
        ChannelValue::Timestamp(t) => t.to_string(),
        // `ChannelValue` is `#[non_exhaustive]`: a channel type added later prints as itself
        // rather than failing to compile a tool that does not know it yet.
        other => format!("{other:?}"),
    }
}

/// The streams a capture holds, and the sample rate each one runs at.
///
/// `smpRate` alone is ambiguous — with `smpMod` = samples-per-period it is a count per cycle
/// — so the nominal frequency is an option, and where the stream advertises nothing the
/// wrap is taken from the counter the capture actually reached.
fn discover_streams(capture: &Capture) -> Vec<Discovered> {
    let mut found: Vec<Discovered> = Vec::new();
    for (_, frame) in &capture.frames {
        let Ok(fr) = Frame::parse(frame) else { continue };
        if fr.ethertype != ETHERTYPE_SV {
            continue;
        }
        let Ok(pdu) = SavPduView::parse(fr.apdu, &Limits::DEFAULT) else { continue };
        for a in pdu.asdus().flatten() {
            match found.iter_mut().find(|d| d.key.dst == fr.dst && d.key.appid == fr.appid && d.key.sv_id == a.sv_id) {
                Some(d) => d.max_smp_cnt = d.max_smp_cnt.max(a.smp_cnt),
                None => found.push(Discovered {
                    key: StreamKey { dst: fr.dst, appid: fr.appid, sv_id: a.sv_id.to_string() },
                    smp_rate: a.smp_rate,
                    smp_mod: a.smp_mod,
                    conf_rev: a.conf_rev,
                    max_smp_cnt: a.smp_cnt,
                }),
            }
        }
    }
    found
}

/// One stream `sv monitor` found in a capture, before the subscriber is configured for it.
struct Discovered {
    key: StreamKey,
    smp_rate: Option<u16>,
    smp_mod: Option<u8>,
    conf_rev: u32,
    max_smp_cnt: u16,
}

impl Discovered {
    /// What `smpCnt` wraps at for this stream, from what it advertises or from what it
    /// reached.
    ///
    /// A `SecPerSmp` stream of more than one second per sample has no samples-per-second
    /// modulus at all; the counter the capture reached is then the only evidence there is.
    fn samples_per_second(&self, freq: u32) -> u32 {
        let observed = || u32::from(self.max_smp_cnt) + 1;
        match (self.smp_rate, self.smp_mod.and_then(SmpMod::from_u8)) {
            (Some(r), Some(SmpMod::SamplesPerSecond)) if r != 0 => u32::from(r),
            (Some(1), Some(SmpMod::SecondsPerSample)) => 1,
            (Some(r), None | Some(SmpMod::SamplesPerPeriod)) if r != 0 => u32::from(r) * freq,
            _ => observed(),
        }
    }
}

fn pcap_info(file: &str) -> Result<(), String> {
    let capture = read(file)?;
    let (mut goose, mut sv, mut other, mut tagged) = (0u64, 0u64, 0u64, 0u64);
    let mut gse_mgmt = 0u64;
    let mut span = (u64::MAX, 0u64);
    for (ts, frame) in &capture.frames {
        span = (span.0.min(*ts), span.1.max(*ts));
        match Frame::parse(frame) {
            Ok(fr) => {
                if fr.vlan.is_some() {
                    tagged += 1;
                }
                match fr.ethertype {
                    ETHERTYPE_GOOSE => goose += 1,
                    ETHERTYPE_SV => sv += 1,
                    ETHERTYPE_GSE_MGMT => gse_mgmt += 1,
                    _ => other += 1,
                }
            }
            Err(_) => other += 1,
        }
    }
    let seconds = if capture.frames.is_empty() { 0.0 } else { (span.1 - span.0) as f64 / 1e9 };
    println!("{file}: {} frames over {seconds:.3} s", capture.frames.len());
    println!("  GOOSE {goose}, sampled values {sv}, other {other}, VLAN-tagged {tagged}");
    if gse_mgmt > 0 {
        // 0x88B9 is Edition 1 GSE management, deprecated in Ed2. Seeing it at all is worth
        // saying: it means an Ed1 device is still on this segment.
        println!("  GSE management (IEC 61850-8-1 Ed1, deprecated) {gse_mgmt}");
    }
    if seconds > 0.0 {
        println!("  {:.0} process-bus frames per second", (goose + sv) as f64 / seconds);
    }
    Ok(())
}

/// The options every `mms` client subcommand shares.
struct MmsOptions {
    fc: Fc,
    /// Whether `--fc` was given. A read has a sensible default; a write does not.
    fc_given: bool,
    password: Option<String>,
    value_type: String,
    timeout: Duration,
    seconds: u64,
    local_tsel: Option<Vec<u8>>,
    remote_tsel: Option<Vec<u8>>,
    rcb: Option<String>,
    buffered: bool,
    data_set: Option<String>,
    intg_pd: Option<u32>,
    gi: bool,
    /// `None` means "ask the server" — see `Control::model`.
    model: Option<ControlModel>,
    orcat: OriginCategory,
    scd: Option<String>,
    ied: Option<String>,
    orident: String,
    synchro: bool,
    interlock: bool,
    test: bool,
    max_size: usize,
    activate: Option<u32>,
    edit: Option<u32>,
    lcb: Option<String>,
    entries: usize,
}

impl Default for MmsOptions {
    fn default() -> MmsOptions {
        MmsOptions {
            fc: Fc::ST,
            fc_given: false,
            password: None,
            value_type: String::from("bool"),
            timeout: Duration::from_secs(30),
            seconds: 30,
            local_tsel: None,
            remote_tsel: None,
            rcb: None,
            buffered: false,
            data_set: None,
            intg_pd: None,
            gi: false,
            model: None,
            orcat: OriginCategory::RemoteControl,
            scd: None,
            ied: None,
            orident: String::from("ied"),
            synchro: false,
            interlock: false,
            test: false,
            max_size: 16 * 1024 * 1024,
            activate: None,
            edit: None,
            lcb: None,
            entries: 1000,
        }
    }
}

fn mms_options(args: &[&str]) -> Result<MmsOptions, String> {
    let mut o = MmsOptions::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value"));
        match *arg {
            "--fc" => {
                let v = value()?;
                o.fc = Fc::parse(&v.to_ascii_uppercase()).ok_or_else(|| format!("unknown functional constraint `{v}`"))?;
                o.fc_given = true;
            }
            "--password" => o.password = Some(value()?.to_string()),
            "--type" => o.value_type = value()?.to_ascii_lowercase(),
            "--timeout" => o.timeout = Duration::from_secs(value()?.parse().map_err(|_| "--timeout needs seconds".to_string())?),
            "--seconds" => o.seconds = value()?.parse().map_err(|_| "--seconds needs a number".to_string())?,
            "--local-tsel" => o.local_tsel = Some(parse_hex(value()?)?),
            "--remote-tsel" => o.remote_tsel = Some(parse_hex(value()?)?),
            "--rcb" => o.rcb = Some(value()?.to_string()),
            "--buffered" => o.buffered = true,
            "--data-set" => o.data_set = Some(value()?.to_string()),
            "--intg-pd" => o.intg_pd = Some(value()?.parse().map_err(|_| "--intg-pd needs milliseconds".to_string())?),
            "--gi" => o.gi = true,
            "--model" => {
                o.model = Some(match value()? {
                    "direct" | "direct-normal" | "1" => ControlModel::DirectNormal,
                    "sbo" | "sbo-normal" | "2" => ControlModel::SboNormal,
                    "direct-enhanced" | "3" => ControlModel::DirectEnhanced,
                    "sbo-enhanced" | "4" => ControlModel::SboEnhanced,
                    other => return Err(format!("unknown control model `{other}`; use direct, sbo, direct-enhanced or sbo-enhanced")),
                });
            }
            "--orcat" => {
                let v = value()?;
                o.orcat = OriginCategory::from_code(v.parse().map_err(|_| format!("--orcat needs a number, not `{v}`"))?);
            }
            "--orident" => o.orident = value()?.to_string(),
            "--synchro" => o.synchro = true,
            "--interlock" => o.interlock = true,
            "--test" => o.test = true,
            "--max-size" => o.max_size = value()?.parse().map_err(|_| "--max-size needs a number of bytes".to_string())?,
            "--activate" => o.activate = Some(value()?.parse().map_err(|_| "--activate needs a group number".to_string())?),
            "--edit" => o.edit = Some(value()?.parse().map_err(|_| "--edit needs a group number".to_string())?),
            "--lcb" => o.lcb = Some(value()?.to_string()),
            "--entries" => o.entries = value()?.parse().map_err(|_| "--entries needs a number".to_string())?,
            "--scd" => o.scd = Some(value()?.to_string()),
            "--ied" => o.ied = Some(value()?.to_string()),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    Ok(o)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("`{s}` is not an even number of hex digits"));
    }
    (0..s.len() / 2).map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2).unwrap_or(""), 16).map_err(|e| e.to_string())).collect()
}

fn mms_connect(host: &str, o: &MmsOptions) -> Result<Client, String> {
    // `--scd` makes the engineering file the configuration, for the station bus as well as
    // for the process bus: the selectors, the AP-title and the AE-qualifier all come out of
    // `Communication/ConnectedAP`, and getting any of them wrong is refused at a layer whose
    // error message says nothing useful. A `-` host means "the IP the file gives too".
    let mut cfg = match (&o.scd, &o.ied) {
        (Some(path), Some(ied)) => {
            let xml = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let scl = scl::Scl::parse(&xml).map_err(|e| format!("{path}: {e}"))?;
            let (cfg, ip) = ClientConfig::from_scl(&scl, ied, None).map_err(|e| format!("{path}: {ied}: {e}"))?;
            if host == "-" {
                let ip = ip.ok_or_else(|| format!("{path}: {ied} has no IP address in the file"))?;
                return connect_with(&ip, cfg, o);
            }
            cfg
        }
        (Some(_), None) | (None, Some(_)) => return Err("--scd and --ied go together".to_string()),
        (None, None) => ClientConfig::default(),
    };
    if host == "-" {
        return Err("a host of `-` needs --scd and --ied to say where to connect".to_string());
    }
    if let Some(t) = &o.local_tsel {
        cfg.association.local.t_sel.clone_from(t);
    }
    if let Some(t) = &o.remote_tsel {
        cfg.association.remote.t_sel.clone_from(t);
    }
    connect_with(host, cfg, o)
}

fn connect_with(host: &str, mut cfg: ClientConfig, o: &MmsOptions) -> Result<Client, String> {
    cfg.association.password.clone_from(&o.password);
    cfg.association.request_timeout_ms = o.timeout.as_millis() as u64;
    cfg.connect_timeout = o.timeout;
    Client::connect_with(host, &cfg).map_err(|e| format!("{host}: {e}"))
}

fn mms_identify(host: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;
    let id = c.identify().map_err(|e| e.to_string())?;
    println!("vendor    {}", id.vendor);
    println!("model     {}", id.model);
    println!("revision  {}", id.revision);
    if let Some(n) = c.negotiated() {
        println!("max PDU   {} octets", n.max_pdu);
        println!("outstanding {}", n.max_outstanding);
    }
    let _ = c.release();
    Ok(())
}

/// `Status` and `GetCapabilityList`: the two questions that need no model.
///
/// A `Status` answer proves all six layers are up without naming a single object, which is
/// why a supervision loop asks it and why it is the first thing to reach for when a link is
/// suspect.
fn mms_status(host: &str, args: &[&str]) -> Result<(), String> {
    use iec61850_rs::proto::mms::{vmd_logical, vmd_physical};
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;
    let s = c.status(false).map_err(|e| e.to_string())?;
    let logical = match s.logical {
        vmd_logical::STATE_CHANGES_ALLOWED => "state-changes-allowed",
        vmd_logical::NO_STATE_CHANGES_ALLOWED => "no-state-changes-allowed",
        vmd_logical::LIMITED_SERVICES_ALLOWED => "limited-services-allowed",
        vmd_logical::SUPPORT_SERVICES_ALLOWED => "support-services-allowed",
        _ => "unknown",
    };
    let physical = match s.physical {
        vmd_physical::OPERATIONAL => "operational",
        vmd_physical::PARTIALLY_OPERATIONAL => "partially-operational",
        vmd_physical::INOPERABLE => "inoperable",
        vmd_physical::NEEDS_COMMISSIONING => "needs-commissioning",
        _ => "unknown",
    };
    println!("logical   {} ({})", logical, s.logical);
    println!("physical  {} ({})", physical, s.physical);
    println!("healthy   {}", s.is_healthy());
    // A server that has not got the service says so with a reject rather than a value, and
    // that is not a reason for this command to fail — the status is the answer asked for.
    match c.capabilities() {
        Ok(caps) if !caps.is_empty() => {
            println!("capabilities");
            for cap in caps {
                println!("  {cap}");
            }
        }
        Ok(_) => println!("capabilities (none)"),
        Err(e) => println!("capabilities  unavailable ({e})"),
    }
    let _ = c.release();
    Ok(())
}

fn mms_browse(host: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;
    let devices = c.server_directory().map_err(|e| e.to_string())?;
    if devices.is_empty() {
        println!("(the server reports no logical devices)");
    }
    for ld in &devices {
        println!("{ld}");
        let names = c.logical_device_directory(ld).map_err(|e| e.to_string())?;
        for name in &names {
            println!("  {name}");
        }
        let sets = c.data_set_directory(ld).unwrap_or_default();
        for set in &sets {
            println!("  data set {set}");
            for member in c.data_set_members(ld, set).unwrap_or_default() {
                println!("    {member}");
            }
        }
        println!("  {} variables, {} data sets", names.len(), sets.len());
    }
    let _ = c.release();
    Ok(())
}

fn mms_read(host: &str, reference: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;
    let value = c.read(reference, o.fc).map_err(|e| format!("{reference}: {e}"))?;
    println!("{reference} = {}", show_value(&value));
    let _ = c.release();
    Ok(())
}

fn mms_write(host: &str, reference: &str, literal: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    // There is no defensible default here. ST and MX are what the process reports and a
    // conforming server refuses a write to them (IEC 61850-7-2 §5.7), so silently
    // defaulting to ST would turn a missing flag into `object-access-denied` from the
    // far end — an error about the server for a mistake in the command line.
    if !o.fc_given {
        return Err("a write needs --fc: settings are SP or SE, configuration CF, description DC, control CO.\n       ST and MX are what the process reports; a conforming server refuses a write to them.".to_string());
    }
    let value = parse_value(&o.value_type, literal)?;
    let mut c = mms_connect(host, &o)?;
    c.write(reference, o.fc, &value).map_err(|e| format!("{reference}: {e}"))?;
    println!("{reference} <- {}", show_value(&value));
    let _ = c.release();
    Ok(())
}

fn mms_report(host: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let mut c = mms_connect(host, &o)?;

    // With --rcb, configure and enable the control block first; otherwise just listen, which
    // is what you want when another client already enabled it.
    if let Some(reference) = &o.rcb {
        let fc = if reference.contains("$BR$") || o.buffered { Fc::BR } else { Fc::RP };
        let mut settings = RcbSettings::new().with_useful_fields().with_trg_ops(TrgOps::EVENTS);
        if let Some(ms) = o.intg_pd {
            settings = settings.with_intg_pd(ms).with_trg_ops(TrgOps::EVENTS.with_integrity(true));
        }
        if let Some(ds) = &o.data_set {
            settings.data_set = Some(ds.clone());
        }
        let rcb = c.enable_rcb(reference, fc, &settings).map_err(|e| format!("{reference}: {e}"))?;
        println!("enabled {} — data set {}, {} ", rcb.reference, rcb.data_set.as_deref().unwrap_or("(none)"), describe_trg_ops(rcb.trg_ops));
        if o.gi {
            c.general_interrogation(reference, fc).map_err(|e| format!("{reference}: {e}"))?;
            println!("general interrogation requested");
        }
    }

    println!("listening for {} s", o.seconds);
    let deadline = std::time::Instant::now() + Duration::from_secs(o.seconds);
    let mut n = 0u64;
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match c.next_unsolicited(left.min(Duration::from_millis(500))) {
            Ok(Some(Unsolicited::Report(r))) => {
                n += 1;
                print_report(n, &r);
            }
            Ok(Some(Unsolicited::CommandTermination(t))) => {
                println!("command termination {} for {}", if t.is_positive() { "+" } else { "-" }, t.control_object());
            }
            Ok(Some(Unsolicited::Other { name, values, .. })) => {
                n += 1;
                println!("report {n} {name} — {} values (not an IEC 61850 report)", values.len());
            }
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    println!("{n} reports");
    if let Some(reference) = &o.rcb {
        let fc = if reference.contains("$BR$") || o.buffered { Fc::BR } else { Fc::RP };
        let _ = c.disable_rcb(reference, fc);
    }
    let _ = c.release();
    Ok(())
}

fn print_report(n: u64, r: &Report) {
    print!("report {n} {}", r.rpt_id);
    if let Some(sq) = r.seq_num {
        print!(" sq={sq}");
    }
    if let Some(t) = r.time_of_entry {
        print!(" t={t}");
    }
    if let Some(ds) = &r.data_set {
        print!(" dataSet={ds}");
    }
    if let Some(rev) = r.conf_rev {
        print!(" confRev={rev}");
    }
    if r.buf_ovfl == Some(true) {
        print!(" BUFFER OVERFLOW");
    }
    if r.is_partial() {
        print!(" (segment {}, more follow)", r.sub_seq_num.unwrap_or(0));
    }
    println!(" — {} of {} members", r.entries.len(), r.data_set_len());
    for e in &r.entries {
        let name = e.reference.clone().unwrap_or_else(|| format!("[{}]", e.index));
        let reason = e.reason.map_or_else(String::new, |r| format!("  ({})", describe_reason(r)));
        println!("    {name} = {}{reason}", show_value(&e.value));
    }
}

fn describe_reason(r: ReasonCode) -> String {
    let mut parts = Vec::new();
    if r.data_change() {
        parts.push("data change");
    }
    if r.quality_change() {
        parts.push("quality change");
    }
    if r.data_update() {
        parts.push("data update");
    }
    if r.integrity() {
        parts.push("integrity");
    }
    if r.general_interrogation() {
        parts.push("general interrogation");
    }
    if parts.is_empty() { String::from("no reason given") } else { parts.join(", ") }
}

fn describe_trg_ops(t: Option<TrgOps>) -> String {
    let Some(t) = t else { return String::from("triggers unknown") };
    let mut parts = Vec::new();
    if t.data_change() {
        parts.push("data change");
    }
    if t.quality_change() {
        parts.push("quality change");
    }
    if t.data_update() {
        parts.push("data update");
    }
    if t.integrity() {
        parts.push("integrity");
    }
    if t.general_interrogation() {
        parts.push("GI");
    }
    if parts.is_empty() { String::from("no triggers") } else { format!("triggers: {}", parts.join(", ")) }
}

fn mms_control(host: &str, reference: &str, literal: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let value = parse_value(&o.value_type, literal)?;
    // The control model is engineered, not guessed: with `--scd` it comes out of the file,
    // and a sequence built on the wrong one silently does nothing at all.
    let mut model = o.model;
    if let (Some(path), Some(ied)) = (&o.scd, &o.ied) {
        let xml = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let scl = scl::Scl::parse(&xml).map_err(|e| format!("{path}: {e}"))?;
        if let Some(m) = scl.model(Some(ied)).ok().and_then(|m| m.control_model(reference)) {
            println!("{reference}: control model {m:?}, from {path}");
            model = Some(m);
        }
    }
    let mut c = mms_connect(host, &o)?;
    // Neither `--model` nor `--scd`: the *server* is asked, because a sequence built on the
    // wrong control model is refused with `ObjectNotSelected` and looks like a broken object.
    let mut control = c.control(reference);
    if let Some(m) = model {
        control = control.model(m);
    }
    let outcome = control.origin(o.orcat, &o.orident).check(Check { synchro: o.synchro, interlock: o.interlock }).test(o.test).execute(&value);
    let _ = c.release();
    match outcome {
        Ok(None) => {
            println!("{reference} <- {} (accepted)", show_value(&value));
            Ok(())
        }
        Ok(Some(t)) => {
            println!("{reference} <- {} (command termination + for {})", show_value(&value), t.control_object());
            Ok(())
        }
        Err(iec61850_rs::Error::ControlRejected { add_cause }) => {
            Err(format!("{reference}: refused — {:?} (AddCause {add_cause})", AddCause::from_code(add_cause)))
        }
        Err(e) => Err(format!("{reference}: {e}")),
    }
}

fn mms_rcb(host: &str, reference: &str, args: &[&str]) -> Result<(), String> {
    let o = mms_options(args)?;
    let fc = if reference.contains("$BR$") || o.buffered { Fc::BR } else { Fc::RP };
    let mut c = mms_connect(host, &o)?;
    let rcb = c.read_rcb(reference, fc).map_err(|e| format!("{reference}: {e}"))?;
    println!("{}", rcb.reference);
    println!("  kind       {}", if rcb.buffered { "buffered (BR)" } else { "unbuffered (RP)" });
    println!("  RptID      {}", rcb.rpt_id.as_deref().unwrap_or("-"));
    println!("  RptEna     {}", rcb.rpt_ena);
    println!("  DatSet     {}", rcb.data_set.as_deref().unwrap_or("-"));
    println!("  ConfRev    {}", rcb.conf_rev.map_or_else(|| String::from("-"), |v| v.to_string()));
    println!("  OptFlds    {}", rcb.opt_flds.map_or_else(|| String::from("-"), describe_opt_flds));
    println!("  TrgOps     {}", describe_trg_ops(rcb.trg_ops));
    println!("  BufTm      {} ms", rcb.buf_tm.map_or_else(|| String::from("-"), |v| v.to_string()));
    println!("  IntgPd     {} ms", rcb.intg_pd.map_or_else(|| String::from("-"), |v| v.to_string()));
    println!("  SqNum      {}", rcb.sq_num.map_or_else(|| String::from("-"), |v| v.to_string()));
    if rcb.buffered {
        println!("  EntryID    {}", rcb.entry_id.as_ref().map_or_else(|| String::from("-"), |b| format!("{b:02X?}")));
        println!("  ResvTms    {}", rcb.resv_tms.map_or_else(|| String::from("-"), |v| v.to_string()));
    } else {
        println!("  Resv       {}", rcb.resv.map_or_else(|| String::from("-"), |v| v.to_string()));
    }
    let _ = c.release();
    Ok(())
}

fn describe_opt_flds(o: OptFlds) -> String {
    let mut parts = Vec::new();
    for (on, name) in [
        (o.sequence_number(), "SqNum"),
        (o.report_time_stamp(), "TimeOfEntry"),
        (o.reason_for_inclusion(), "ReasonCode"),
        (o.data_set_name(), "DatSet"),
        (o.data_reference(), "DataRef"),
        (o.buffer_overflow(), "BufOvfl"),
        (o.entry_id(), "EntryID"),
        (o.conf_revision(), "ConfRev"),
        (o.segmentation(), "segmentation"),
    ] {
        if on {
            parts.push(name);
        }
    }
    if parts.is_empty() { String::from("none") } else { parts.join(", ") }
}

/// Turn a command-line literal into the `Data` value the `--type` names.
fn parse_value(kind: &str, literal: &str) -> Result<IedValue, String> {
    Ok(match kind {
        "bool" => IedValue::Boolean(match literal {
            "1" | "true" | "on" => true,
            "0" | "false" | "off" => false,
            other => return Err(format!("`{other}` is not a boolean; use true/false")),
        }),
        "int" => IedValue::Integer(literal.parse().map_err(|_| format!("`{literal}` is not an integer"))?),
        "uint" => IedValue::Unsigned(literal.parse().map_err(|_| format!("`{literal}` is not an unsigned integer"))?),
        "float" => IedValue::Float32(literal.parse().map_err(|_| format!("`{literal}` is not a number"))?),
        "string" => IedValue::VisibleString(literal.to_string()),
        other => return Err(format!("unknown --type `{other}`; use bool, int, uint, float or string")),
    })
}

/// One line for a decoded value: the type it is, never coerced into another.
fn show_value(v: &IedValue) -> String {
    match v {
        IedValue::Boolean(b) => format!("{b}"),
        IedValue::Integer(i) => format!("{i}"),
        IedValue::Unsigned(u) => format!("{u}"),
        IedValue::Float32(f) => format!("{f}"),
        IedValue::Float64(f) => format!("{f}"),
        IedValue::VisibleString(s) | IedValue::MmsString(s) => format!("{s:?}"),
        IedValue::UtcTime(t) => format!("{t}"),
        IedValue::BitString { unused, bytes } => match v.as_dbpos() {
            Some(p) => format!("{p:?}"),
            None => match v.as_quality() {
                Some(q) => format!("{q:?}"),
                None => format!("bitstring {bytes:02X?} ({unused} unused)"),
            },
        },
        IedValue::OctetString(b) | IedValue::BinaryTime(b) => format!("{b:02X?}"),
        IedValue::Array(m) | IedValue::Structure(m) => {
            let inner: Vec<String> = m.iter().map(show_value).collect();
            format!("{{ {} }}", inner.join(", "))
        }
        IedValue::Other { tag, bytes, .. } => format!("[{tag}] {bytes:02X?}"),
    }
}

/// `1`, `2` or `2.1` as an [`Edition`].
fn parse_edition(value: &str) -> Result<Edition, String> {
    match value {
        "1" => Ok(Edition::Ed1),
        "2" => Ok(Edition::Ed2),
        "2.1" => Ok(Edition::Ed2_1),
        other => Err(format!("unknown edition `{other}`; expected 1, 2 or 2.1")),
    }
}

/// How an edition prints in the simulator's banner.
fn edition_name(edition: Edition) -> &'static str {
    match edition {
        Edition::Ed1 => "Edition 1",
        Edition::Ed2 => "Edition 2",
        Edition::Ed2_1 => "Edition 2.1",
        _ => "Edition ?",
    }
}

fn scl_validate(file: &str, args: &[&str]) -> Result<(), String> {
    let mut freq = 50u32;
    let mut edition = Edition::Ed2_1;
    let mut warnings_are_errors = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value"));
        match *arg {
            "--freq" => freq = value()?.parse().map_err(|_| "--freq needs a number".to_string())?,
            "--edition" => edition = parse_edition(value()?)?,
            "--strict" => warnings_are_errors = true,
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    let xml = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let report = scl::validate(&xml, freq, edition).map_err(|e| e.to_string())?;
    println!("{file}: SCL {}, {} IED(s)", report.scl_version, report.ieds.len());
    for f in &report.findings {
        println!("  {f}");
    }
    let (errors, warnings) = (report.errors().count(), report.warnings().count());
    if errors == 0 && warnings == 0 {
        println!("  no problems found");
        return Ok(());
    }
    println!("  {errors} error(s), {warnings} warning(s)");
    if errors > 0 || (warnings_are_errors && warnings > 0) { Err(format!("{} problem(s)", errors + warnings)) } else { Ok(()) }
}

fn scl_show(file: &str, ied: Option<&str>) -> Result<(), String> {
    let xml = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let model = IedModel::from_scl_with(&xml, ied, LoadOptions::default()).map_err(|e| e.to_string())?;
    println!(
        "IED {} ({} {}, config {})",
        model.name,
        model.manufacturer.as_deref().unwrap_or("-"),
        model.ied_type.as_deref().unwrap_or("-"),
        model.config_version.as_deref().unwrap_or("-")
    );
    for ap in &model.access_points {
        match &ap.address {
            Some(a) => {
                let sel = |s: &Option<Vec<u8>>| {
                    s.as_ref().map_or_else(
                        || "-".to_string(),
                        |v| {
                            v.iter().fold(String::new(), |mut acc, b| {
                                use std::fmt::Write;
                                let _ = write!(acc, "{b:02X}");
                                acc
                            })
                        },
                    )
                };
                println!(
                    "  AccessPoint {} ip={} tsel={} ssel={} psel={} ap-title={} ae-qual={}",
                    ap.name,
                    a.ip.as_deref().unwrap_or("-"),
                    sel(&a.t_sel),
                    sel(&a.s_sel),
                    sel(&a.p_sel),
                    a.ap_title.as_ref().map_or_else(|| "-".to_string(), |t| t.iter().map(ToString::to_string).collect::<Vec<_>>().join(".")),
                    a.ae_qualifier.map_or_else(|| "-".to_string(), |q| q.to_string())
                );
            }
            None => println!("  AccessPoint {} (no OSI address)", ap.name),
        }
    }
    for ld in &model.logical_devices {
        println!("  LD {} (inst {})", ld.name, ld.inst);
        for ln in &ld.logical_nodes {
            println!("    LN {} [{}] {} data objects", ln.name, ln.ln_type, ln.data_objects.len());
            for object in &ln.data_objects {
                // The common data class is what says *what kind of thing* an object is —
                // `DPC` is a controllable double point, `MV` a measurand — and it is the
                // first thing anyone reading an unfamiliar file wants beside the name.
                println!("      DO {} [{}]", object.name, if object.cdc.is_empty() { "-" } else { object.cdc.as_str() });
            }
            for ds in &ln.data_sets {
                println!("      DataSet {} ({} members)", ds.name, ds.members.len());
                for m in &ds.members {
                    println!("        {}", model.fcda_reference(&ld.name, m));
                }
            }
            for g in &ln.gse_controls {
                let addr = g.address.as_ref().map_or_else(|| "no address".to_string(), |a| format!("{} appid={:#06x} vlan={}", a.mac, a.appid, a.vlan_id));
                println!("      GSEControl {} confRev={} {}", g.name, g.conf_rev, addr);
            }
            for s in &ln.smv_controls {
                let addr = s.address.as_ref().map_or_else(|| "no address".to_string(), |a| format!("{} appid={:#06x}", a.mac, a.appid));
                let kind = if s.multicast { "multicast" } else { "unicast" };
                println!("      SampledValueControl {} {kind} smvID={} smpRate={} nofASDU={} {}", s.name, s.smv_id, s.smp_rate, s.nof_asdu, addr);
            }
            for r in &ln.report_controls {
                println!("      ReportControl {} buffered={} confRev={} bufTime={}ms", r.name, r.buffered, r.conf_rev, r.buf_time_ms);
            }
        }
    }
    if !model.diagnostics.is_empty() {
        println!("  {} diagnostic(s); run `ied scl validate` for detail", model.diagnostics.len());
    }
    Ok(())
}

/// What `ied mu` was asked to generate.
struct MuOptions {
    profile: SvProfile,
    frames: u32,
    sv_id: String,
    appid: u16,
    amplitude: i32,
    /// Nominal frequency of the synthetic waveform, in Hz.
    freq: f64,
    gm: Option<[u8; 8]>,
    refr_tm: bool,
}

impl MuOptions {
    fn parse(args: &[&str]) -> Result<MuOptions, String> {
        let mut o = MuOptions {
            profile: SvProfile::LE_80_50HZ,
            frames: 1000,
            sv_id: String::from("MU01"),
            appid: 0x4000,
            amplitude: 100_000,
            freq: 0.0,
            gm: None,
            refr_tm: false,
        };
        let mut freq = None;
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value"));
            match *arg {
                "--profile" => {
                    o.profile = match value()? {
                        "le80-50" => SvProfile::LE_80_50HZ,
                        "le80-60" => SvProfile::LE_80_60HZ,
                        "le256-50" => SvProfile::LE_256_50HZ,
                        "le256-60" => SvProfile::LE_256_60HZ,
                        "f4800s2" => SvProfile::F4800S2I4U4,
                        "f14400s6" => SvProfile::F14400S6I4U4,
                        other => return Err(format!("unknown profile `{other}`")),
                    }
                }
                "--frames" => o.frames = value()?.parse().map_err(|_| "--frames needs a number".to_string())?,
                "--sv-id" => o.sv_id = value()?.to_string(),
                "--appid" => o.appid = u16::from_str_radix(value()?.trim_start_matches("0x"), 16).map_err(|_| "--appid needs hex".to_string())?,
                "--amplitude" => o.amplitude = value()?.parse().map_err(|_| "--amplitude needs a number".to_string())?,
                "--freq" => freq = Some(value()?.parse().map_err(|_| "--freq needs a number".to_string())?),
                "--refr-tm" => o.refr_tm = true,
                "--gm" => o.gm = Some(parse_hex8(value()?)?),
                other => return Err(format!("unknown option `{other}`")),
            }
        }
        // 9-2LE counts 80 or 256 samples per *nominal cycle*, so its sample rate implies
        // the frequency the profile was built for; IEC 61869-9 fixes the rate in absolute
        // terms and the waveform frequency is a free choice. Either way `--freq` wins.
        o.freq = freq.unwrap_or(match o.profile.samples_per_second {
            4800 | 15_360 if o.profile.smp_mod.is_none() => 60.0,
            _ => 50.0,
        });
        Ok(o)
    }
}

fn parse_hex8(hex: &str) -> Result<[u8; 8], String> {
    let bad = || "--gm needs 16 hex digits".to_string();
    let mut id = [0u8; 8];
    if hex.len() != 16 {
        return Err(bad());
    }
    for (i, slot) in id.iter_mut().enumerate() {
        *slot = hex.get(i * 2..i * 2 + 2).ok_or_else(bad).and_then(|p| u8::from_str_radix(p, 16).map_err(|_| bad()))?;
    }
    Ok(id)
}

fn scl_subs(file: &str, ied: &str, args: &[&str]) -> Result<(), String> {
    let mut freq = 50u32;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--freq" => {
                freq = it.next().copied().ok_or("--freq needs a value")?.parse().map_err(|_| "--freq needs a number".to_string())?;
            }
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    let xml = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let subs = scl::subscriptions(&xml, ied, freq).map_err(|e| e.to_string())?;
    println!("{ied} subscribes to {} GOOSE and {} sampled-value stream(s)", subs.goose.len(), subs.sv.len());
    for s in subs.goose.iter().chain(&subs.sv) {
        let rate = s.samples_per_second.map_or_else(String::new, |r| format!(" rate={r}/s"));
        let channels = s.layout.as_ref().map_or_else(String::new, |l| format!(" {} channels/{} octets per ASDU", l.channels().len(), l.len()));
        println!("  {} from {} ({})", s.identifier, s.publisher, s.control_block);
        println!("    {} appid={:#06x} confRev={}{rate}{channels}", s.dst, s.appid, s.conf_rev);
        for x in &s.ext_refs {
            let target = format!(
                "{}{}{}.{}{}",
                x.prefix,
                x.ln_class.as_deref().unwrap_or("LLN0"),
                x.ln_inst,
                x.do_name.as_deref().unwrap_or("-"),
                x.da_name.as_deref().map(|d| format!(".{d}")).unwrap_or_default()
            );
            println!("    <- {target}{}", x.int_addr.as_deref().map(|a| format!(" [{a}]")).unwrap_or_default());
        }
    }
    // The other half of the same question: an `LGOS` naming nothing, or naming a control
    // block this IED does not subscribe to, sits at `St = false` for ever without saying why.
    let scl = scl::Scl::parse(&xml).map_err(|e| e.to_string())?;
    let model = scl.model(Some(ied)).map_err(|e| e.to_string())?;
    let nodes = model.supervision();
    if !nodes.is_empty() {
        println!("supervision:");
        for n in &nodes {
            match &n.control_block {
                Some(cb) => {
                    let watched = subs.goose.iter().chain(&subs.sv).any(|s| n.watches(&s.control_block));
                    println!("  {} ({}) -> {cb}{}", n.node, n.ln_class, if watched { "" } else { "   [not subscribed]" });
                }
                None => println!("  {} ({}) -> nothing engineered", n.node, n.ln_class),
            }
        }
    }
    if subs.unresolved.is_empty() {
        Ok(())
    } else {
        for d in &subs.unresolved {
            println!("  unresolved: {d}");
        }
        Err(format!("{} unresolved binding(s)", subs.unresolved.len()))
    }
}

fn merging_unit(file: &str, args: &[&str]) -> Result<(), String> {
    let opt = MuOptions::parse(args)?;
    let header = FrameHeader {
        dst: MacAddr([0x01, 0x0C, 0xCD, 0x04, (opt.appid >> 8) as u8 & 0x01, opt.appid as u8]),
        src: MacAddr([0x02, 0, 0, 0, 0, 1]),
        vlan: Some(VlanTag::DEFAULT),
        ethertype: ETHERTYPE_SV,
        appid: opt.appid,
        reserved1: 0,
        reserved2: 0,
    };
    let mut publisher = Publisher::new(PublisherConfig::new(header, opt.sv_id.clone(), opt.profile).with_time_fields(opt.refr_tm, opt.gm.is_some()))
        .map_err(|e| e.to_string())?;
    publisher.set_smp_synch(SmpSynch::Global).map_err(|e| e.to_string())?;
    if let Some(id) = opt.gm {
        publisher.set_gm_identity(id);
    }

    let mut out = Writer::create(file).map_err(|e| format!("{file}: {e}"))?;
    let interval = opt.profile.frame_interval_nanos();
    let per_frame = publisher.asdus_per_frame();
    let mut nanos = 1_700_000_000u64 * 1_000_000_000;
    let mut sample_index = 0u32;

    for _ in 0..opt.frames {
        // A three-phase sinusoid at nominal frequency, 120 degrees apart, with the currents
        // a tenth of the voltages — enough to look like a merging unit to a dissector and
        // to exercise the whole encode path.
        let blocks: Vec<[u8; 64]> = (0..per_frame)
            .map(|k| {
                let i = sample_index + k as u32;
                let phase = |offset: f64| {
                    let turn = f64::from(i) / f64::from(opt.profile.samples_per_second) * opt.freq * core::f64::consts::TAU;
                    (f64::from(opt.amplitude) * (turn + offset).sin()) as i32
                };
                let (a, b, c) = (phase(0.0), phase(-2.0944), phase(2.0944));
                PhsMeas1 {
                    currents: [a / 10, b / 10, c / 10, 0],
                    current_quality: [iec61850_rs::Quality::GOOD; 4],
                    voltages: [a, b, c, 0],
                    voltage_quality: [iec61850_rs::Quality::GOOD; 4],
                }
                .encode()
            })
            .collect();
        let refs: Vec<&[u8]> = blocks.iter().map(<[u8; 64]>::as_slice).collect();
        if opt.refr_tm {
            publisher.set_refr_tm(UtcTime::from_unix_nanos(nanos, TimeQuality::SYNCHRONIZED));
        }
        publisher.publish(Instant(nanos), &refs).map_err(|e| e.to_string())?;
        if let Some(frame) = publisher.poll_transmit() {
            out.write(nanos, frame).map_err(|e| e.to_string())?;
        }
        sample_index += per_frame as u32;
        nanos += interval;
    }
    out.finish().map_err(|e| e.to_string())?;
    println!(
        "wrote {} frames to {file}: svID={} {} samples/s, {per_frame} ASDU/frame, {} frames/s, {} Hz waveform",
        opt.frames,
        opt.sv_id,
        opt.profile.samples_per_second,
        opt.profile.frames_per_second(),
        opt.freq
    );
    Ok(())
}
