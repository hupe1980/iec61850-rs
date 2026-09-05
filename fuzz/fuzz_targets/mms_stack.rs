#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! The whole OSI stack under MMS, from arbitrary bytes: TPKT framing and reassembly, COTP,
//! session, presentation, ACSE and the MMS PDUs. Anything that decodes must also re-encode
//! and decode again without panicking, which is where a codec that disagrees with itself
//! shows up.

use iec61850_rs::common::Limits;
use iec61850_rs::proto::mms::control::{ControlRequest, LastApplError};
use iec61850_rs::proto::mms::report::{Report, ReportAssembler};
use iec61850_rs::proto::mms::{Mms, Unconfirmed};
use iec61850_rs::proto::osi::acse::Apdu;
use iec61850_rs::proto::osi::cotp::{Reassembler, Tpdu};
use iec61850_rs::proto::osi::presentation::Ppdu;
use iec61850_rs::proto::osi::session::Spdu;
use iec61850_rs::proto::osi::tpkt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The framing layer, fed in two halves so the split-header path is exercised too.
    let mut reader = tpkt::Reader::new();
    let (a, b) = data.split_at(data.len() / 2);
    reader.push(a);
    let _ = reader.next_tpdu();
    reader.push(b);
    let mut reassembler = Reassembler::new(65_535);
    while let Ok(Some(tpdu)) = reader.next_tpdu() {
        let tpdu = tpdu.to_vec();
        if let Ok(pdu) = Tpdu::parse(&tpdu) {
            let mut re = Vec::new();
            if pdu.write(&mut re).is_ok() {
                let _ = Tpdu::parse(&re);
            }
            if let Tpdu::Data { eot, payload } = pdu {
                if let Ok(Some(tsdu)) = reassembler.push(eot, payload) {
                    decode_session(tsdu);
                    reassembler.take();
                }
            }
        }
    }
    // And every layer on its own, so a target that never gets past TPKT still fuzzes them.
    decode_session(data);
    let _ = Ppdu::parse(data, true);
    if let Ok(a) = Apdu::parse(data) {
        let _ = a.to_vec();
    }
    if let Ok(m) = Mms::parse(data, &Limits::DEFAULT) {
        let re = m.to_vec().unwrap();
        let again = Mms::parse(&re, &Limits::DEFAULT).unwrap();
        assert_eq!(again.to_vec().unwrap(), re, "the MMS encoder must be a fixed point");
        // An information report is where the IEC 61850 layer starts: whatever a report
        // decodes to must encode back to the same values, or a field is being read at the
        // wrong offset and every value after it is misattributed.
        if let Mms::Unconfirmed(Unconfirmed::InformationReport { results, .. }) = &m {
            if let Ok(report) = Report::parse(results, &Limits::DEFAULT) {
                let values = report.to_values().expect("a decoded report must re-encode");
                assert_eq!(Report::from_values(&values).unwrap(), report, "the report codec must be a fixed point");
                // Feeding the same segment over and over must neither complete a report that
                // is not complete nor grow the assembler past its bound.
                let mut assembler = ReportAssembler::new(2);
                for _ in 0..8 {
                    if let Some(whole) = assembler.push(report.clone()) {
                        let _ = whole.to_values();
                    }
                    assert!(assembler.pending() <= 2, "the assembler must stay inside its bound");
                }
            }
        }
    }
    // The control structures, from the same arbitrary bytes read as a `Data` value.
    if let Ok(values) = iec61850_rs::proto::data::decode_all(data, &Limits::DEFAULT) {
        if let Some(v) = values.first() {
            if let Ok(r) = ControlRequest::from_value(v) {
                assert_eq!(ControlRequest::from_value(&r.to_value()).unwrap(), r, "the control codec must be a fixed point");
            }
            if let Ok(e) = LastApplError::from_value(v) {
                assert_eq!(LastApplError::from_value(&e.to_value()).unwrap(), e);
            }
            let _ = Report::from_values(&values);
        }
    }
});

fn decode_session(bytes: &[u8]) {
    let Ok(spdu) = Spdu::parse(bytes) else { return };
    let mut re = Vec::new();
    if spdu.write(&mut re).is_ok() {
        let _ = Spdu::parse(&re);
    }
    let (payload, handshake) = match spdu {
        Spdu::Connect(ref c) | Spdu::Accept(ref c) => (c.user_data, true),
        Spdu::DataTransfer(p) => (p, false),
        _ => return,
    };
    if let Ok(ppdu) = Ppdu::parse(payload, handshake) {
        let Ok(re) = ppdu.to_vec() else { return };
        let _ = Ppdu::parse(&re, handshake);
    }
}
