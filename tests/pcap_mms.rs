//! The reference MMS capture (`specs/pcap/mms.pcap`, 165 TPKT packets over one association),
//! decoded through every layer and re-encoded **byte for byte**.
//!
//! This is the strongest check available on the OSI stack without a second implementation to
//! talk to: TPKT framing, COTP class 0, the session CONNECT/ACCEPT and its GIVE TOKENS +
//! DATA TRANSFER pair, the presentation context negotiation and its PDV lists, the ACSE
//! association, and the MMS PDUs — all of it against traffic a real client and a real server
//! actually exchanged, with the octets they wrote as the oracle.
//!
//! Skips when `specs/` is absent, which is what CI sees.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use iec61850_rs::common::Limits;
use iec61850_rs::proto::mms::{ConfirmedRequest, ConfirmedResponse, Mms, ObjectName, Unconfirmed, VariableAccess};
use iec61850_rs::proto::osi::acse::Apdu;
use iec61850_rs::proto::osi::cotp::Tpdu;
use iec61850_rs::proto::osi::presentation::Ppdu;
use iec61850_rs::proto::osi::session::Spdu;
use iec61850_rs::proto::osi::{Oid, tpkt};

/// The TCP payloads of the capture, in file order, split by direction.
///
/// The capture is a clean single connection with no retransmission and no reordering, so
/// "in file order" is the stream — real reassembly belongs to the socket adapter, not here.
fn tcp_payloads(path: &std::path::Path) -> Vec<(bool, Vec<u8>)> {
    let mut out = Vec::new();
    for (_, frame) in common::read_pcap(path) {
        // Ethernet II, IPv4, TCP — the only thing in this capture.
        if frame.len() < 34 || u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
            continue;
        }
        let ihl = usize::from(frame[14] & 0x0F) * 4;
        if frame[23] != 6 {
            continue;
        }
        // The IP total length, not the frame length: a bare ACK is padded to the 60-octet
        // Ethernet minimum, and reading the padding as payload is how a stream reader ends
        // up decoding six zero octets as a TPKT header.
        let ip_end = 14 + usize::from(u16::from_be_bytes([frame[16], frame[17]]));
        let tcp = 14 + ihl;
        let data_off = usize::from(frame[tcp + 12] >> 4) * 4;
        let payload = &frame[tcp + data_off..ip_end.min(frame.len())];
        if payload.is_empty() {
            continue;
        }
        // The client is the side that connected to port 102.
        let dst_port = u16::from_be_bytes([frame[tcp + 2], frame[tcp + 3]]);
        out.push((dst_port == 102, payload.to_vec()));
    }
    out
}

/// Re-encode `decoded` and compare it with the octets it came from.
///
/// The OSI layers below BER re-encode byte for byte. The BER layers do too *unless* the peer
/// wrote a length non-minimally — this server always spends two octets on a long-form length
/// even when one would do (`82 00 96` where `81 96` says the same thing), which BER permits
/// and DER does not. Normalising that is right, so what is asserted for those is the next
/// strongest thing: the re-encoding is a **fixed point** (decoding and re-encoding it again
/// changes nothing) and is never longer than what arrived.
fn same_or_normalised(re: &[u8], original: &[u8], layer: &str, counters: &mut Counters) {
    if re == original {
        counters.byte_identical += 1;
        return;
    }
    assert!(re.len() <= original.len(), "{layer}: a normalised encoding must not grow: {} vs {}", re.len(), original.len());
    counters.normalised += 1;
}

/// Decode one TPDU through the whole stack and require every layer to re-encode exactly.
///
/// `handshake` says whether a presentation CP/CPA is expected, which the session SPDU type
/// already told us.
fn check_layers(tpdu: &[u8], counters: &mut Counters) {
    let cotp = Tpdu::parse(tpdu).expect("COTP");
    let mut re = Vec::new();
    cotp.write(&mut re).expect("re-encode COTP");
    assert_eq!(re, tpdu, "COTP re-encoding differs");
    counters.byte_identical += 1;

    let payload = match cotp {
        Tpdu::ConnectionRequest(_) => {
            counters.cr += 1;
            return;
        }
        Tpdu::ConnectionConfirm(_) => {
            counters.cc += 1;
            return;
        }
        Tpdu::Data { eot, payload } => {
            assert!(eot, "this capture never segments a TSDU");
            payload
        }
        other => panic!("unexpected TPDU {other:?}"),
    };

    let spdu = Spdu::parse(payload).expect("session");
    let mut re = Vec::new();
    spdu.write(&mut re).expect("re-encode session");
    assert_eq!(re, payload, "session re-encoding differs");
    counters.byte_identical += 1;

    let (ppdu_bytes, handshake) = match spdu {
        Spdu::Connect(ref c) | Spdu::Accept(ref c) => (c.user_data, true),
        Spdu::DataTransfer(p) => (p, false),
        other => panic!("unexpected SPDU {other:?}"),
    };

    let ppdu = Ppdu::parse(ppdu_bytes, handshake).expect("presentation");
    let re = ppdu.to_vec().expect("re-encode presentation");
    same_or_normalised(&re, ppdu_bytes, "presentation", counters);
    let again = Ppdu::parse(&re, handshake).expect("presentation, re-decoded").to_vec().expect("re-encode again");
    assert_eq!(again, re, "presentation re-encoding is not a fixed point");

    let pdvs = match &ppdu {
        Ppdu::Connect(cp) => {
            counters.cp += 1;
            assert_eq!(cp.context_for(Oid::MMS_ABSTRACT_SYNTAX), Some(3), "MMS is context 3 in this capture");
            assert_eq!(cp.context_for(Oid::ACSE_ABSTRACT_SYNTAX), Some(1));
            cp.user_data.clone()
        }
        Ppdu::Accept(cp) => {
            counters.cpa += 1;
            assert!(cp.all_accepted(), "the server accepted both contexts");
            cp.user_data.clone()
        }
        Ppdu::UserData(p) => p.clone(),
        Ppdu::Reject(_) => panic!("this capture's association was accepted"),
    };

    for pdv in pdvs {
        let value = pdv.values.single().expect("single-ASN1-type");
        // Context 1 is ACSE, context 3 is MMS — that is what the CP negotiated.
        if pdv.context_id == 1 {
            let acse = Apdu::parse(value).expect("ACSE");
            let re = acse.to_vec().expect("re-encode ACSE");
            same_or_normalised(&re, value, "ACSE", counters);
            assert_eq!(Apdu::parse(&re).expect("ACSE, re-decoded").to_vec().unwrap(), re, "ACSE re-encoding is not a fixed point");
            let mms = match &acse {
                Apdu::Associate(a) => {
                    counters.aarq += 1;
                    assert_eq!(a.context_name, Some(Oid::MMS_APPLICATION_CONTEXT_9506));
                    a.mms_pdu()
                }
                Apdu::AssociateResponse(a) => {
                    counters.aare += 1;
                    assert!(a.accepted(), "the association was accepted");
                    a.mms_pdu()
                }
                _ => None,
            };
            if let Some(bytes) = mms {
                check_mms(bytes, counters);
            }
        } else {
            check_mms(value, counters);
        }
    }
}

fn check_mms(bytes: &[u8], counters: &mut Counters) {
    let pdu = Mms::parse(bytes, &Limits::DEFAULT).expect("MMS");
    let re = pdu.to_vec().expect("re-encode MMS");
    same_or_normalised(&re, bytes, "MMS", counters);
    let again = Mms::parse(&re, &Limits::DEFAULT).expect("MMS, re-decoded").to_vec().expect("re-encode again");
    assert_eq!(again, re, "MMS re-encoding is not a fixed point");
    match pdu {
        Mms::InitiateRequest(i) => {
            counters.initiate += 1;
            assert_eq!(i.local_detail, Some(32_000));
            assert_eq!(i.version, 1);
        }
        Mms::InitiateResponse(_) => counters.initiate_response += 1,
        Mms::ConfirmedRequest { service, .. } => {
            counters.requests += 1;
            match service {
                ConfirmedRequest::Read { .. } => counters.reads += 1,
                ConfirmedRequest::Write { .. } => counters.writes += 1,
                ConfirmedRequest::Identify => counters.identifies += 1,
                ConfirmedRequest::GetNameList { .. } => counters.name_lists += 1,
                ConfirmedRequest::GetNamedVariableListAttributes(_) => counters.list_attributes += 1,
                _ => counters.other_services += 1,
            }
        }
        Mms::ConfirmedResponse { service, .. } => {
            counters.responses += 1;
            if let ConfirmedResponse::Read { results, .. } = service {
                counters.access_results += results.len();
                assert!(results.iter().all(|r| r.value().is_some() || matches!(r, iec61850_rs::proto::mms::AccessResult::Failure(_))));
            }
        }
        Mms::Unconfirmed(Unconfirmed::InformationReport { access, results }) => {
            counters.reports += 1;
            counters.access_results += results.len();
            if let VariableAccess::VariableListName(ObjectName::DomainSpecific { domain, .. }) = access {
                assert!(["KIRKLAND", "BELLEVUE"].contains(&domain), "unexpected domain {domain}");
                counters.domains.insert(domain.to_string());
            }
        }
        _ => counters.other_pdus += 1,
    }
}

#[derive(Debug, Default)]
struct Counters {
    cr: u32,
    cc: u32,
    cp: u32,
    cpa: u32,
    aarq: u32,
    aare: u32,
    initiate: u32,
    initiate_response: u32,
    requests: u32,
    responses: u32,
    reports: u32,
    reads: u32,
    writes: u32,
    identifies: u32,
    name_lists: u32,
    list_attributes: u32,
    other_services: u32,
    other_pdus: u32,
    access_results: usize,
    /// Encodings that came back exactly as they arrived.
    byte_identical: u32,
    /// Encodings that came back with a length written minimally where the peer had not.
    normalised: u32,
    /// The MMS domains the reports name.
    domains: std::collections::BTreeSet<String>,
}

#[test]
fn every_packet_of_the_reference_capture_decodes_and_re_encodes_byte_for_byte() {
    let Some(path) = common::spec("pcap/mms.pcap") else { return };
    let payloads = tcp_payloads(&path);
    assert!(!payloads.is_empty(), "the capture holds TCP payloads");

    // One TPKT reader per direction: a TPKT header may arrive in a segment of its own, and
    // in this capture it always does.
    let (mut client, mut server) = (tpkt::Reader::new(), tpkt::Reader::new());
    let mut counters = Counters::default();
    let mut packets = 0u32;
    for (from_client, payload) in &payloads {
        let reader = if *from_client { &mut client } else { &mut server };
        reader.push(payload);
        while let Some(tpdu) = reader.next_tpdu().expect("TPKT") {
            let tpdu = tpdu.to_vec();
            check_layers(&tpdu, &mut counters);
            packets += 1;
        }
    }
    assert_eq!(client.buffered(), 0, "no partial packet is left over");
    assert_eq!(server.buffered(), 0);

    // What the capture is known to contain. tshark's own field counts agree: 823
    // `mms.AccessResult`, 115 `mms.informationReport_element`, 23 confirmed request/response
    // pairs, 12 `mms.read_element` (six each way), four writes, 14 `mms.identify_element`.
    assert_eq!(packets, 165, "{counters:#?}");
    assert_eq!((counters.cr, counters.cc), (1, 1), "one transport connection");
    assert_eq!((counters.cp, counters.cpa), (1, 1), "one presentation handshake");
    assert_eq!((counters.aarq, counters.aare), (1, 1), "one association");
    assert_eq!((counters.initiate, counters.initiate_response), (1, 1));
    assert_eq!((counters.requests, counters.responses), (23, 23), "every request is answered");
    assert_eq!(counters.reports, 115, "the capture is mostly information reports");
    assert_eq!((counters.reads, counters.writes, counters.identifies), (6, 4, 7));
    assert_eq!((counters.name_lists, counters.list_attributes), (2, 4));
    assert_eq!(counters.other_services, 0, "every service in this capture is one this codec models");
    assert_eq!(counters.other_pdus, 0);
    assert_eq!(counters.access_results, 823, "every value the server reported");
    assert_eq!(counters.domains.len(), 2, "KIRKLAND and BELLEVUE");

    // The headline: of 656 encodings across five layers, 653 come back byte for byte. The
    // three that do not are the PDUs where this server spent two octets on a length that
    // fits one — BER allows it, DER does not, and normalising it is right.
    assert_eq!(counters.byte_identical, 653, "{counters:#?}");
    assert_eq!(counters.normalised, 3, "{counters:#?}");
    eprintln!("mms capture: {packets} packets, {} byte-identical encodings, {} normalised", counters.byte_identical, counters.normalised);
}

/// The same capture, driven through the **association state machine** rather than through
/// the codecs one layer at a time.
///
/// The codec test above proves every PDU decodes and re-encodes. It says nothing about
/// *sequencing* — that a client sends its session CONNECT only after the CC, that the CPA is
/// what establishes the association, that a response releases the invoke identifier it
/// answers. There is no server here to talk to, so the capture plays both parts: the real
/// server's bytes are fed to our client, the real client's bytes to our server, and each is
/// required to reach `Established` and to see exactly the services the capture contains.
/// What each end *sends* is discarded — the capture is the peer, not a mirror.
#[test]
fn the_association_state_machine_follows_the_reference_capture() {
    use iec61850_rs::common::Instant;
    use iec61850_rs::proto::mms::association::{Association, AssociationConfig, AssociationEvent, CloseReason};

    let Some(path) = common::spec("pcap/mms.pcap") else { return };
    let payloads = tcp_payloads(&path);
    let now = Instant::ZERO;

    let mut client = Association::client(AssociationConfig::default());
    let mut server = Association::server(AssociationConfig::default());
    client.start(now).expect("start");
    // Neither end's own output is used: the capture is the other side of both.
    while client.poll_transmit().is_some() {}
    while server.poll_transmit().is_some() {}

    let (mut responses, mut reports, mut requests) = (0u32, 0u32, 0u32);
    let mut server_requests = 0u32;
    let mut client_responses = 0u32;
    let (mut client_up, mut server_up) = (false, false);
    for (from_client, payload) in &payloads {
        let end = if *from_client { &mut server } else { &mut client };
        end.on_bytes(now, payload);
        while end.poll_transmit().is_some() {}
        while let Some(event) = end.poll_event() {
            match event {
                AssociationEvent::Established(n) => {
                    assert_eq!(n.mms_context, 3, "MMS is presentation context 3 in this capture");
                    if *from_client { server_up = true } else { client_up = true }
                }
                AssociationEvent::Response { .. } => {
                    responses += 1;
                    if !*from_client {
                        client_responses += 1;
                    }
                }
                AssociationEvent::Unconfirmed { .. } => reports += 1,
                AssociationEvent::Request { .. } => {
                    if *from_client {
                        requests += 1;
                    } else {
                        server_requests += 1;
                    }
                }
                AssociationEvent::Malformed { error, .. } => panic!("the association could not decode a PDU the codec test accepts: {error}"),
                AssociationEvent::Closed(CloseReason::ProtocolError) => panic!("the state machine rejected real traffic"),
                other => panic!("unexpected event {other:?}"),
            }
        }
    }

    assert!(client_up, "the client end never associated");
    assert!(server_up, "the server end never associated");
    // The capture is **bidirectional**: both peers issue confirmed services and both send
    // information reports, which is normal for the MMS profile and is exactly why the
    // association is one type with a `Role` rather than two. The 23 requests, 23 responses
    // and 115 reports the codec test counts are split across the two directions, and the
    // totals have to add up to the same numbers.
    assert_eq!((requests + server_requests, responses, reports), (23, 23, 115), "every service in the capture reached an end");
    assert_eq!((requests, server_requests), (11, 12), "both peers issue confirmed services");
    assert_eq!((client_responses, responses - client_responses), (11, 12));
    assert_eq!(client.stats().responses_received + server.stats().responses_received, 23);
    assert_eq!(client.stats().reports_received + server.stats().reports_received, 115);
    // 165 TPKT packets out of 330 TCP payloads: this capture splits every header into a
    // segment of its own, so the stream reader earned its place on every single packet.
    assert_eq!(client.stats().packets_received + server.stats().packets_received, 165);
    assert_eq!(payloads.len(), 330, "and each of those 165 arrived in two segments");
    // The capture's client never releases; the association is still up when the file ends.
    assert!(client.is_established() && server.is_established());
}

/// The reference capture's 115 information reports are **not** IEC 61850 reports.
///
/// They are ICCP data-set reports: the association is between two control centres, the
/// domains are `KIRKLAND` and `BELLEVUE`, and the values are plain data-set members with no
/// `RptID` or `OptFlds` in front of them. A client-side classifier that decoded them as
/// IEC 61850 reports would invent a report identifier out of the first value and misread
/// every field after it — so what this pins is that it does not.
#[test]
fn the_capture_s_reports_are_not_mistaken_for_iec_61850_reports() {
    use iec61850_rs::client::Unsolicited;
    use iec61850_rs::common::Limits;

    let Some(path) = common::spec("pcap/mms.pcap") else { return };
    let payloads = tcp_payloads(&path);
    let (mut client, mut server) = (tpkt::Reader::new(), tpkt::Reader::new());
    let (mut classified, mut as_61850) = (0u32, 0u32);

    for (from_client, payload) in &payloads {
        let reader = if *from_client { &mut client } else { &mut server };
        reader.push(payload);
        while let Some(tpdu) = reader.next_tpdu().expect("TPKT") {
            let tpdu = tpdu.to_vec();
            let Ok(Tpdu::Data { payload, .. }) = Tpdu::parse(&tpdu) else { continue };
            let Ok(Spdu::DataTransfer(ppdu)) = Spdu::parse(payload) else { continue };
            let Ok(Ppdu::UserData(pdvs)) = Ppdu::parse(ppdu, false) else { continue };
            for pdv in pdvs {
                if pdv.context_id == 1 {
                    continue;
                }
                let Some(bytes) = pdv.values.single() else { continue };
                let Some(item) = Unsolicited::from_pdu(bytes, &Limits::DEFAULT) else { continue };
                classified += 1;
                match item {
                    Unsolicited::Report(_) => as_61850 += 1,
                    Unsolicited::CommandTermination(_) => panic!("this capture carries no controls"),
                    Unsolicited::Other { name, values, .. } => {
                        assert!(name.starts_with("KIRKLAND/") || name.starts_with("BELLEVUE/"), "unexpected report name {name}");
                        assert!(!values.is_empty());
                    }
                }
            }
        }
    }
    assert_eq!(classified, 115, "every information report was classified");
    assert_eq!(as_61850, 0, "and none of them was claimed to be an IEC 61850 report");
}
