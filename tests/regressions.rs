//! Every input a fuzzer once crashed on, replayed as an ordinary test.
//!
//! `cargo fuzz` writes a crashing input to `fuzz/artifacts/<target>/crash-<hash>`, which is a
//! working file: gitignored, hash-named, and gone the moment someone cleans the directory.
//! Once the bug is fixed the input stops being an artifact and becomes the only cheap proof
//! that it stays fixed, so it is renamed after the bug and moved to `fuzz/regressions/`, and
//! this test replays all of them through the same entry points the target uses.
//!
//! The directory is not part of the published crate (`exclude` in `Cargo.toml`), so the test
//! skips rather than fails when it is absent — the same rule `tests/concepts.rs` follows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use iec61850_rs::common::Limits;

/// Files under `fuzz/regressions/<target>`, or an empty list when the directory is absent.
fn corpus(target: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/regressions").join(target);
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "bin")).collect();
    files.sort();
    files
}

#[test]
fn every_mms_stack_regression_still_decodes_without_panicking() {
    let files = corpus("mms_stack");
    if files.is_empty() {
        return; // not a checkout of the repository
    }
    for file in &files {
        let data = std::fs::read(file).unwrap();
        mms_stack(&data);
    }
}

/// The server half, from the same corpus rule: an input the `mms_server` target crashed on is
/// replayed through the request path it crashed in.
#[cfg(all(feature = "server", feature = "scl"))]
#[test]
fn every_mms_server_regression_still_answers_without_panicking() {
    use iec61850_rs::common::Instant;
    use iec61850_rs::proto::mms::Mms;
    use iec61850_rs::server::{Acsi, Ied};

    let files = corpus("mms_server");
    if files.is_empty() {
        return;
    }
    for file in &files {
        let data = std::fs::read(file).unwrap();
        let ied = Ied::from_scl(FUZZ_MODEL, Some("IED1")).unwrap();
        let mut acsi = Acsi::new(ied);
        for (n, chunk) in data.chunks(64).enumerate() {
            let assoc = (n % 2) as u64 + 1;
            let now = Instant::ZERO.plus_millis(n as u64 + 1);
            if let Ok(Mms::ConfirmedRequest { invoke_id, service }) = Mms::parse(chunk, &Limits::DEFAULT) {
                let answer = acsi.request(assoc, now, &service);
                // The property the crash broke: an answer the encoder refuses is a request a
                // client waits for ever on, which is worse than any error response.
                answer.encode(invoke_id).expect("every answer must encode");
            }
            for (_, pdu) in acsi.commit(now) {
                Mms::parse(&pdu, &Limits::DEFAULT).expect("every report must decode");
            }
        }
    }
}

/// The model `fuzz/fuzz_targets/mms_server.rs` uses, trimmed to what these inputs reach.
#[cfg(all(feature = "server", feature = "scl"))]
const FUZZ_MODEL: &str = r#"<?xml version="1.0"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <Header id="f"/>
  <IED name="IED1"><AccessPoint name="P1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LLN0_T"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_T" lnClass="LLN0"><DO name="Mod" type="INC_T"/></LNodeType>
    <DOType id="INC_T" cdc="INC"><DA name="stVal" fc="ST" bType="INT32"/></DOType>
  </DataTypeTemplates>
</SCL>"#;

#[cfg(feature = "goose")]
#[test]
fn every_goose_regression_still_decodes_without_panicking() {
    for file in corpus("goose_frame") {
        let data = std::fs::read(&file).unwrap();
        if let Ok(frame) = iec61850_rs::proto::ethernet::Frame::parse(&data) {
            if let Ok(pdu) = iec61850_rs::proto::goose::GoosePduView::parse(frame.apdu) {
                let _ = pdu.all_data_owned(&Limits::DEFAULT);
                let _ = pdu.member_count_matches();
            }
        }
    }
}

/// The body of `fuzz/fuzz_targets/mms_stack.rs`, minus the libfuzzer harness.
fn mms_stack(data: &[u8]) {
    use iec61850_rs::proto::mms::control::{ControlRequest, LastApplError};
    use iec61850_rs::proto::mms::report::Report;
    use iec61850_rs::proto::mms::{Mms, Unconfirmed};
    use iec61850_rs::proto::osi::acse::Apdu;
    use iec61850_rs::proto::osi::cotp::{Reassembler, Tpdu};
    use iec61850_rs::proto::osi::presentation::Ppdu;
    use iec61850_rs::proto::osi::session::Spdu;
    use iec61850_rs::proto::osi::tpkt;

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
    decode_session(data);
    let _ = Ppdu::parse(data, true);
    if let Ok(a) = Apdu::parse(data) {
        let _ = a.to_vec();
    }
    if let Ok(m) = Mms::parse(data, &Limits::DEFAULT) {
        let re = m.to_vec().unwrap();
        let again = Mms::parse(&re, &Limits::DEFAULT).unwrap();
        assert_eq!(again.to_vec().unwrap(), re, "the MMS encoder must be a fixed point");
        if let Mms::Unconfirmed(Unconfirmed::InformationReport { results, .. }) = &m {
            if let Ok(report) = Report::parse(results, &Limits::DEFAULT) {
                let values = report.to_values().expect("a decoded report must re-encode");
                assert_eq!(Report::from_values(&values).unwrap(), report, "the report codec must be a fixed point");
            }
        }
    }
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
}
