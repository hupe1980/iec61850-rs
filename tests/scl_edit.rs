//! The SCL editing DOM: an untouched document is its input byte for byte, an edit changes only
//! the bytes it is about, references move with a rename, and every edit undoes exactly.
//!
//! The `OpenSCD` corpus and `xmllint` checks skip when the reference corpus or `xmllint` is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::process::Command;
use std::time::Instant;

use iec61850_rs::common::{Edition, Error, Fc};
use iec61850_rs::model::{Fcda, GseAddress, IedModel, SmvAddress};
use iec61850_rs::proto::ethernet::MacAddr;
use iec61850_rs::scl::{self, CbRef, ControlKind, Document, ExtRefSource, Hitem, LnRef, NewElement};
use proptest::prelude::*;

const FIXTURE: &str = include_str!("fixtures/edit.scd");

fn doc() -> Document {
    Document::parse(FIXTURE).unwrap()
}

/// Lines that differ between two texts of the same line count, as `(before, after)`.
fn changed_lines(before: &str, after: &str) -> Vec<(String, String)> {
    let (a, b): (Vec<_>, Vec<_>) = (before.lines().collect(), after.lines().collect());
    assert_eq!(a.len(), b.len(), "line count changed:\n{after}");
    a.iter().zip(&b).filter(|(x, y)| x != y).map(|(x, y)| (x.trim().to_string(), y.trim().to_string())).collect()
}

/// Lines `after` has that `before` does not, when `before` is a subsequence of `after`.
fn added_lines(before: &str, after: &str) -> Vec<String> {
    let mut added = Vec::new();
    let mut old = before.lines().peekable();
    for line in after.lines() {
        if old.peek() == Some(&line) {
            old.next();
        } else {
            added.push(line.to_string());
        }
    }
    assert!(old.next().is_none(), "lines were removed, not only added:\n{after}");
    added
}

/// Error findings per code — the shape a differential check compares, since `at` and
/// `message` legitimately carry the names an edit changes.
fn error_codes(text: &str) -> BTreeMap<String, usize> {
    let report = scl::validate(text, 50, Edition::Ed2_1).unwrap();
    let mut out = BTreeMap::new();
    for f in report.errors() {
        *out.entry(format!("{:?}", f.code)).or_insert(0) += 1;
    }
    out
}

// --- User story 1: an untouched file comes back byte for byte ---------------------------------

#[test]
fn corpus_round_trips_byte_for_byte() {
    let Some(dir) = common::reference_dir("fixtures/openscd") else { return };
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let d = Document::from_bytes(bytes.clone()).unwrap();
        assert_eq!(d.as_str().as_bytes(), bytes.as_slice(), "{}", path.display());
        let scl = d.scl().unwrap();
        for name in scl.ied_names() {
            scl.model(Some(&name)).unwrap();
        }
        files += 1;
    }
    assert!(files >= 5, "the OpenSCD corpus has at least five SCD files");
}

#[test]
fn lexical_detail_survives_round_trip_and_unrelated_edits() {
    let text = "\u{FEFF}<?xml version='1.0' encoding=\"UTF-8\"?>\r\n\
        <?tool hint?>\r\n\
        <!-- head -->\r\n\
        <SCL  xmlns=\"http://www.iec.ch/61850/2003/SCL\" xmlns:e='urn:x' version=\"2007\" revision=\"C\" release=\"5\" >\r\n\
        \t<Header id='h&apos;1' toolID=\"t&#9;x\"></Header>\r\n\
        \t<Private type=\"x\"><![CDATA[a<b]]>&#65;&amp;</Private>\r\n\
        \t<e:Ext xmlns:e=\"urn:y\" e:a = 'v' />\r\n\
        \t<IED name=\"A\"/>\r\n\
        </SCL>\r\n";
    let mut d = Document::parse(text).unwrap();
    assert_eq!(d.as_str(), text);
    d.rename_ied("A", "B").unwrap();
    let out = d.as_str();
    assert_eq!(out, text.replace("<IED name=\"A\"/>", "<IED name=\"B\"/>"));
    for kept in [
        "\u{FEFF}<?xml version='1.0'",
        "<?tool hint?>",
        "<!-- head -->",
        "<SCL  xmlns",
        "revision=\"C\" release=\"5\" >",
        "id='h&apos;1'",
        "toolID=\"t&#9;x\"></Header>",
        "<![CDATA[a<b]]>&#65;&amp;",
        "e:a = 'v' />",
        "\r\n",
    ] {
        assert!(out.contains(kept), "lost {kept:?}");
    }
}

#[test]
fn input_that_is_not_utf8_or_not_well_formed_is_refused() {
    assert!(matches!(Document::from_bytes(vec![0xff, 0xfe, b'<', 0]), Err(Error::Scl(_))));
    assert!(matches!(Document::parse("<SCL><IED></SCL>"), Err(Error::Scl(_))));
}

// SR-001
#[test]
fn a_dtd_is_refused_so_no_entity_is_expanded_or_fetched() {
    let laughs = "<?xml version=\"1.0\"?><!DOCTYPE SCL [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">\
        <!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\"><!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\">]><SCL a=\"&d;&d;&d;&d;\"/>";
    let xxe = "<?xml version=\"1.0\"?><!DOCTYPE SCL [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><SCL>&x;</SCL>";
    for text in [laughs, xxe] {
        let t = Instant::now();
        assert!(matches!(Document::parse(text), Err(Error::Scl(_))));
        assert!(matches!(scl::Scl::parse(text), Err(Error::Scl(_))), "the read-only loader refuses it too");
        assert!(t.elapsed().as_millis() < 500);
    }
}

// SR-002
#[test]
fn deep_nesting_is_parsed_or_refused_without_overflowing_the_stack() {
    let depth = 200_000;
    let worker = std::thread::spawn(move || {
        let mut text = String::with_capacity(depth * 8);
        for _ in 0..depth {
            text.push_str("<a>");
        }
        for _ in 0..depth {
            text.push_str("</a>");
        }
        // The read-only loader shares the parser and the risk: it must return, either way.
        let _ = scl::Scl::parse(&text).map(|s| s.ied_names());
        match Document::parse(text) {
            Ok(mut d) => {
                let r = d.edit("deep", |tx| {
                    let innermost = tx.root().descendants().last().unwrap_or(tx.root());
                    tx.set_attribute(innermost, "x", "1");
                    Ok(())
                });
                assert!(r.is_ok());
            }
            Err(e) => assert!(matches!(e, Error::Scl(_))),
        }
    });
    assert!(worker.join().is_ok(), "the thread completed instead of overflowing its stack");
}

// --- User story 2: an edit touches only what it changes ----------------------------------------

#[test]
fn rename_ied_moves_every_reference_and_nothing_else() {
    let mut d = doc();
    let n = d.rename_ied("Pub", "Bay1").unwrap();
    assert_eq!(n, 5);
    let changed = changed_lines(FIXTURE, d.as_str());
    assert_eq!(
        changed,
        [
            ("<LNode iedName=\"Pub\" ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\"/>", "<LNode iedName=\"Bay1\" ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\"/>"),
            ("<ConnectedAP iedName=\"Pub\" apName=\"AP1\">", "<ConnectedAP iedName=\"Bay1\" apName=\"AP1\">"),
            ("<IED name=\"Pub\">", "<IED name=\"Bay1\">"),
            (
                "<ExtRef iedName=\"Pub\" ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\" doName=\"Pos\" daName=\"stVal\" serviceType=\"GOOSE\" srcLDInst=\"LD0\" srcLNClass=\"LLN0\" srcCBName=\"gcb1\" intAddr=\"in1\"/>",
                "<ExtRef iedName=\"Bay1\" ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\" doName=\"Pos\" daName=\"stVal\" serviceType=\"GOOSE\" srcLDInst=\"LD0\" srcLNClass=\"LLN0\" srcCBName=\"gcb1\" intAddr=\"in1\"/>"
            ),
            ("<Val>PubLD0/LLN0$GO$gcb1</Val>", "<Val>Bay1LD0/LLN0$GO$gcb1</Val>"),
        ]
        .map(|(a, b)| (a.to_string(), b.to_string()))
    );
    assert_eq!(error_codes(d.as_str()), error_codes(FIXTURE));
    let subs = scl::subscriptions(d.as_str(), "Sub", 50).unwrap();
    assert_eq!(subs.goose.len(), 1, "the subscription still resolves after the rename");

    // The subscriber side: ClientLN and IEDName follow too.
    let mut d = doc();
    assert_eq!(d.rename_ied("Sub", "Hmi").unwrap(), 4);
    assert!(d.as_str().contains("<IEDName>Hmi</IEDName>") && d.as_str().contains("<ClientLN iedName=\"Hmi\""));
}

#[test]
fn rename_refuses_bad_or_taken_names_and_leaves_the_document_alone() {
    let mut d = doc();
    assert!(matches!(d.rename_ied("Pub", "Sub"), Err(Error::Scl(_))));
    assert!(matches!(d.rename_ied("Pub", "None"), Err(Error::Scl(_))));
    assert!(matches!(d.rename_ied("Pub", "1abc"), Err(Error::Scl(_))));
    assert!(matches!(d.rename_ied("Nobody", "X"), Err(Error::NotFound(_))));
    assert_eq!(d.as_str(), FIXTURE);
    assert_eq!(d.history().len(), 0);
}

#[test]
fn remove_ied_cleans_up_communication_bindings_and_allocations() {
    let mut d = doc();
    d.remove_ied("Pub").unwrap();
    let t = d.as_str();
    assert!(!t.contains("IED name=\"Pub\""));
    assert!(!t.contains("iedName=\"Pub\""), "no reference to the removed IED is left:\n{t}");
    assert!(t.contains("<LNode iedName=\"None\" lnClass=\"XCBR\" lnInst=\"1\"/>"));
    assert!(t.contains("<ExtRef intAddr=\"in1\"/>"), "the ExtRef keeps its intAddr and loses its source");
    assert!(t.contains("<ConnectedAP iedName=\"Sub\" apName=\"AP1\"/>"));
    IedModel::from_scl(t, Some("Sub")).unwrap();

    let mut d = doc();
    d.remove_ied("Sub").unwrap();
    assert!(!d.as_str().contains("<IEDName>Sub</IEDName>") && !d.as_str().contains("ClientLN"));
}

#[test]
fn data_set_and_member_edits_keep_control_blocks_consistent() {
    let lln0 = LnRef::lln0();
    let member = |da: &str| Fcda {
        ld_inst: "LD0".into(),
        prefix: String::new(),
        ln_class: "XCBR".into(),
        ln_inst: "1".into(),
        do_name: "Pos".into(),
        da_name: Some(da.into()),
        fc: Fc::ST,
        ix: None,
    };
    let mut d = doc();
    d.rename_data_set("Pub", "LD0", &lln0, "ds1", "dsTrip").unwrap();
    let changed = changed_lines(FIXTURE, d.as_str());
    assert_eq!(changed.len(), 3, "the data set, its report block and its GOOSE block: {changed:?}");
    assert!(changed.iter().all(|(_, after)| after.contains("dsTrip")));

    d.add_fcda("Pub", "LD0", &lln0, "dsTrip", &member("q")).unwrap();
    assert!(d.as_str().contains("<FCDA ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\" doName=\"Pos\" daName=\"q\" fc=\"ST\"/>"));
    assert!(matches!(d.add_fcda("Pub", "LD0", &lln0, "dsTrip", &member("q")), Err(Error::Scl(_))));
    d.remove_fcda("Pub", "LD0", &lln0, "dsTrip", &member("q")).unwrap();
    assert!(matches!(d.remove_fcda("Pub", "LD0", &lln0, "dsTrip", &member("stVal")), Err(Error::Scl(_))), "the last member stays");

    d.remove_data_set("Pub", "LD0", &lln0, "dsTrip").unwrap();
    assert!(!d.as_str().contains("datSet="));
    d.add_data_set("Pub", "LD0", &lln0, "dsNew", &[member("stVal")]).unwrap();
    let t = d.as_str();
    let ds = t.find("<DataSet name=\"dsNew\">").unwrap();
    assert!(ds < t.find("<ReportControl").unwrap(), "a data set goes before the control blocks, as the schema orders them");
    // The blocks that lost their data set really have none, and the validator says so.
    assert!(error_codes(t).len() >= error_codes(FIXTURE).len());
}

#[test]
fn control_block_rename_follows_communication_subscribers_and_values() {
    let mut d = doc();
    let lln0 = LnRef::lln0();
    d.rename_control("Pub", "LD0", &lln0, ControlKind::Gse, "gcb1", "gcbTrip").unwrap();
    let changed = changed_lines(FIXTURE, d.as_str());
    assert_eq!(changed.len(), 4, "GSEControl, GSE, ExtRef srcCBName, LGOS value: {changed:?}");
    assert!(d.as_str().contains("<Val>PubLD0/LLN0$GO$gcbTrip</Val>"));
    assert_eq!(scl::subscriptions(d.as_str(), "Sub", 50).unwrap().goose.len(), 1);

    d.remove_control("Pub", "LD0", &lln0, ControlKind::Gse, "gcbTrip").unwrap();
    let t = d.as_str();
    assert!(!t.contains("GSEControl") && !t.contains("<GSE "));
    assert!(t.contains("serviceType=\"GOOSE\" intAddr=\"in1\"/>"), "the ExtRef keeps its data source:\n{t}");

    let gse = NewElement::new("GSEControl").attr("name", "gcb2").attr("datSet", "ds1").attr("appID", "g2").attr("confRev", "1");
    d.add_control("Pub", "LD0", &lln0, ControlKind::Gse, &gse).unwrap();
    assert!(matches!(d.add_control("Pub", "LD0", &LnRef::new("", "XCBR", "1"), ControlKind::Gse, &gse), Err(Error::Scl(_))));
    let rcb = NewElement::new("ReportControl").attr("name", "rcb2").child(NewElement::new("OptFields"));
    d.add_control("Pub", "LD0", &lln0, ControlKind::Report, &rcb).unwrap();
    let t = d.as_str();
    assert!(t.find("name=\"rcb2\"").unwrap() < t.find("name=\"gcb2\"").unwrap(), "schema order: ReportControl before GSEControl");
}

#[test]
fn ext_refs_bind_and_unbind() {
    let mut d = doc();
    let lln0 = LnRef::lln0();
    let source = ExtRefSource {
        ied: "Pub".into(),
        ld: "LD0".into(),
        prefix: String::new(),
        ln_class: "XCBR".into(),
        ln_inst: "1".into(),
        do_name: "Pos".into(),
        da_name: Some("q".into()),
        service_type: Some("GOOSE".into()),
        src_cb: Some(CbRef { ld: "LD0".into(), ln: LnRef::lln0(), name: "gcb1".into() }),
    };
    d.bind_ext_ref("Sub", "LD0", &lln0, "in2", &source).unwrap();
    assert!(d.as_str().contains(
        "<ExtRef intAddr=\"in2\" iedName=\"Pub\" ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\" doName=\"Pos\" daName=\"q\" serviceType=\"GOOSE\" srcLDInst=\"LD0\" srcLNClass=\"LLN0\" srcCBName=\"gcb1\"/>"
    ));
    d.unbind_ext_ref("Sub", "LD0", &lln0, "in1").unwrap();
    assert!(d.as_str().contains("<ExtRef intAddr=\"in1\"/>"));
    assert!(matches!(d.unbind_ext_ref("Sub", "LD0", &lln0, "nope"), Err(Error::NotFound(_))));
}

#[test]
fn addresses_are_updated_in_place_or_created_where_the_schema_wants_them() {
    let mut d = doc();
    let mac = MacAddr::parse("01-0C-CD-01-00-42").unwrap();
    let gse = GseAddress { mac, appid: 0x42, vlan_id: 0x10, vlan_priority: 6, min_time_ms: Some(4), max_time_ms: Some(1000) };
    d.set_gse_address("Pub", "LD0", "gcb1", &gse).unwrap();
    let t = d.as_str();
    for want in ["01-0C-CD-01-00-42</P>", "<P type=\"APPID\">0042</P>", "<P type=\"VLAN-ID\">010</P>", "<P type=\"VLAN-PRIORITY\">6</P>"] {
        assert!(t.contains(want), "{want}");
    }
    let min = t.find("<MinTime unit=\"s\" multiplier=\"m\">4</MinTime>").unwrap();
    assert!(t.find("</Address>\n\t\t\t\t</GSE>").is_none() && min > t.find("<P type=\"VLAN-PRIORITY\">6</P>").unwrap());
    assert!(error_codes(t).is_empty());

    // An SMV block that has no entry yet gets one under the right ConnectedAP.
    let mut d = doc();
    let smv = NewElement::new("SampledValueControl")
        .attr("name", "msv1")
        .attr("datSet", "ds1")
        .attr("smvID", "sv1")
        .attr("smpRate", "80")
        .attr("nofASDU", "1")
        .attr("confRev", "1")
        .child(NewElement::new("SmvOpts"));
    d.add_control("Pub", "LD0", &LnRef::lln0(), ControlKind::Smv, &smv).unwrap();
    let sv = SmvAddress { mac: MacAddr::parse("01-0C-CD-04-00-01").unwrap(), appid: 0x4000, vlan_id: 0, vlan_priority: 4 };
    d.set_smv_address("Pub", "LD0", "msv1", &sv).unwrap();
    let t = d.as_str();
    assert!(t.find("<SMV ldInst=\"LD0\" cbName=\"msv1\">").unwrap() > t.find("</GSE>").unwrap(), "SMV after GSE");

    d.set_ap_address("Pub", "AP1", "IP", "10.0.0.9").unwrap();
    d.set_ap_address("Pub", "AP1", "IP-SUBNET", "255.255.255.0").unwrap();
    d.set_ap_address("Sub", "AP1", "IP", "10.0.0.2").unwrap();
    let t = d.as_str();
    assert!(t.contains("<P type=\"IP\">10.0.0.9</P>") && t.contains("<P type=\"IP-SUBNET\">255.255.255.0</P>"));
    assert!(
        t.contains(
            "<ConnectedAP iedName=\"Sub\" apName=\"AP1\">\n\t\t\t\t<Address>\n\t\t\t\t\t<P type=\"IP\">10.0.0.2</P>\n\t\t\t\t</Address>\n\t\t\t</ConnectedAP>"
        ),
        "{t}"
    );
}

#[test]
fn ln_add_and_remove_follow_data_sets_and_bindings() {
    let mut d = doc();
    d.add_ln("Pub", "LD0", &LnRef::new("Q0", "CSWI", "1"), "XCBR_T").unwrap();
    assert!(d.as_str().contains("<LN prefix=\"Q0\" lnClass=\"CSWI\" inst=\"1\" lnType=\"XCBR_T\"/>"));
    let mut d = doc();
    d.remove_ln("Pub", "LD0", &LnRef::new("", "XCBR", "1")).unwrap();
    let t = d.as_str();
    assert!(!t.contains("<DataSet") && !t.contains("datSet="), "the data set left empty goes, with its references:\n{t}");
    assert!(t.contains("<ExtRef intAddr=\"in1\"/>"));
    assert!(t.contains("<LNode iedName=\"None\" lnClass=\"XCBR\" lnInst=\"1\"/>"));
}

#[test]
fn history_items_append_in_order() {
    let mut d = doc();
    let item = |v: &str| Hitem {
        version: "1".into(),
        revision: v.into(),
        when: "2026-11-09T10:00:00Z".into(),
        who: Some("alice".into()),
        what: Some("x".into()),
        why: None,
    };
    d.add_history(&item("B")).unwrap();
    d.add_history(&item("C")).unwrap();
    let hitem = |r: &str| format!("\t\t\t<Hitem version=\"1\" revision=\"{r}\" when=\"2026-11-09T10:00:00Z\" who=\"alice\" what=\"x\"/>");
    let header = format!("\t<Header id=\"bay\" version=\"1\" revision=\"A\">\n\t\t<History>\n{}\n{}\n\t\t</History>\n\t</Header>\n", hitem("B"), hitem("C"));
    assert_eq!(d.as_str(), FIXTURE.replace("\t<Header id=\"bay\" version=\"1\" revision=\"A\"/>\n", &header));

    // Into a header that already has history, after the last item.
    let mut d = Document::parse(
        FIXTURE
            .replace("revision=\"A\"/>", "revision=\"A\">\n\t\t<History>\n\t\t\t<Hitem version=\"1\" revision=\"A\" when=\"t\"/>\n\t\t</History>\n\t</Header>"),
    )
    .unwrap();
    let before = d.as_str().to_string();
    d.add_history(&item("B")).unwrap();
    assert_eq!(added_lines(&before, d.as_str()), [hitem("B")]);
}

// SR-007, on files this repository did not write.
#[test]
fn renaming_every_corpus_ied_leaves_no_reference_behind_and_no_new_error() {
    let Some(dir) = common::reference_dir("fixtures/openscd") else { return };
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let mut d = Document::parse(text.clone()).unwrap();
        let names = d.scl().unwrap().ied_names();
        for name in &names {
            d.rename_ied(name, &format!("{name}X")).unwrap();
        }
        let out = d.as_str();
        for name in &names {
            for stale in [format!("iedName=\"{name}\""), format!("<IED name=\"{name}\""), format!(">{name}</IEDName>")] {
                assert!(!out.contains(&stale), "{}: {stale} left behind", path.display());
            }
        }
        assert_eq!(error_codes(out), error_codes(&text), "{}", path.display());
        assert_eq!(out.lines().count(), text.lines().count(), "{}: a rename adds or removes no line", path.display());
        while d.undo() {}
        assert_eq!(d.as_str(), text, "{}: undo restores the original", path.display());
    }
}

/// Schema errors of a text, without the file name and line numbers, as a multiset.
fn xsd_errors(xsd: &std::path::Path, text: &str, dir: &std::path::Path, tag: &str) -> Option<BTreeMap<String, usize>> {
    let file = dir.join(format!("{tag}.scd"));
    std::fs::write(&file, text).ok()?;
    let out = Command::new("xmllint").arg("--noout").arg("--schema").arg(xsd).arg(&file).output().ok()?;
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(&out.stderr).lines().filter(|l| l.contains("validity error")) {
        let msg = line.split_once("validity error :").map_or(line, |(_, m)| m).trim().to_string();
        *map.entry(msg).or_insert(0) += 1;
    }
    Some(map)
}

// FR-004, judged by a validating parser this crate did not write.
#[test]
fn edited_corpus_files_gain_no_schema_error() {
    let (Some(dir), Some(xsd)) = (common::reference_dir("fixtures/openscd"), common::reference("scl/SCL.xsd")) else { return };
    if Command::new("xmllint").arg("--version").output().is_err() || common::reference("scl/SCL_BaseSimpleTypes.xsd").is_none() {
        return;
    }
    let tmp = std::env::temp_dir().join(format!("iec61850-scl-edit-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let mut d = Document::parse(text.clone()).unwrap();
        let names = d.scl().unwrap().ied_names();
        for name in &names {
            d.rename_ied(name, &format!("{name}X")).unwrap();
        }
        d.add_history(&Hitem {
            version: "2".into(),
            revision: "A".into(),
            when: "2026-11-09T10:00:00Z".into(),
            who: None,
            what: Some("rename".into()),
            why: None,
        })
        .unwrap();
        let stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let before = xsd_errors(&xsd, &text, &tmp, &format!("{stem}-before")).unwrap();
        let after = xsd_errors(&xsd, d.as_str(), &tmp, &format!("{stem}-after")).unwrap();
        for (msg, n) in &after {
            assert!(before.get(msg).copied().unwrap_or(0) >= *n, "{}: new schema error {msg}", path.display());
        }
    }
    std::fs::remove_dir_all(&tmp).ok();
}

#[test]
fn fixture_is_schema_valid_before_and_after_every_operation() {
    let Some(xsd) = common::reference("scl/SCL.xsd") else { return };
    if Command::new("xmllint").arg("--version").output().is_err() || common::reference("scl/SCL_BaseSimpleTypes.xsd").is_none() {
        return;
    }
    let tmp = std::env::temp_dir().join(format!("iec61850-scl-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let mut d = doc();
    let lln0 = LnRef::lln0();
    d.rename_ied("Pub", "Bay1").unwrap();
    d.rename_control("Bay1", "LD0", &lln0, ControlKind::Gse, "gcb1", "gcbTrip").unwrap();
    d.rename_data_set("Bay1", "LD0", &lln0, "ds1", "dsTrip").unwrap();
    let gse =
        GseAddress { mac: MacAddr::parse("01-0C-CD-01-00-07").unwrap(), appid: 7, vlan_id: 1, vlan_priority: 4, min_time_ms: Some(2), max_time_ms: Some(2000) };
    d.set_gse_address("Bay1", "LD0", "gcbTrip", &gse).unwrap();
    d.set_ap_address("Sub", "AP1", "IP", "10.0.0.2").unwrap();
    d.add_history(&Hitem { version: "1".into(), revision: "B".into(), when: "2026-11-09T10:00:00Z".into(), who: Some("t".into()), what: None, why: None })
        .unwrap();
    d.add_ln("Sub", "LD0", &LnRef::new("", "IHMI", "2"), "IHMI_T").unwrap();
    d.remove_ln("Bay1", "LD0", &LnRef::new("", "XCBR", "1")).unwrap();
    let errors = xsd_errors(&xsd, d.as_str(), &tmp, "fixture").unwrap();
    assert!(errors.is_empty(), "{errors:?}\n{}", d.as_str());
    std::fs::remove_dir_all(&tmp).ok();
}

// SR-005
#[test]
fn a_large_station_renames_in_linear_time() {
    let (ieds, refs_per_ied) = (2_000, 25);
    let mut text = String::from("<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\">\n  <Header id=\"big\"/>\n");
    for i in 0..ieds {
        writeln!(text, "  <IED name=\"IED{i}\">\n    <AccessPoint name=\"AP1\">\n      <Server>\n        <LDevice inst=\"LD0\">\n          <LN0 lnClass=\"LLN0\" inst=\"\" lnType=\"T\">\n            <Inputs>").unwrap();
        for r in 0..refs_per_ied {
            writeln!(text, "              <ExtRef iedName=\"IED0\" ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\" doName=\"Pos\" intAddr=\"i{r}\"/>").unwrap();
        }
        text.push_str("            </Inputs>\n          </LN0>\n        </LDevice>\n      </Server>\n    </AccessPoint>\n  </IED>\n");
    }
    text.push_str("</SCL>\n");
    let mut d = Document::parse(text).unwrap();
    let t = Instant::now();
    let n = d.rename_ied("IED0", "Hub").unwrap();
    let took = t.elapsed();
    assert_eq!(n, 1 + ieds * refs_per_ied);
    assert!(!d.as_str().contains("iedName=\"IED0\""));
    assert!(took.as_secs() < 10, "rename of {} references took {took:?}", ieds * refs_per_ied);
    eprintln!("rename of {} references in {} bytes: {took:?}", ieds * refs_per_ied, d.as_str().len());
}

// --- SR-006 / SC-004: undo after any sequence of edits is exact ------------------------------

#[derive(Clone, Debug)]
enum Op {
    Set(usize, &'static str, String),
    Remove(usize),
    Insert(usize, String),
    Text(usize, String),
}

fn op() -> impl Strategy<Value = Op> {
    let value = "[a-zA-Z0-9 &<>\"'\t\n\u{e4}\u{20ac}]{0,12}";
    prop_oneof![
        (any::<usize>(), prop::sample::select(vec!["desc", "name", "x"]), value).prop_map(|(i, k, v)| Op::Set(i, k, v)),
        any::<usize>().prop_map(Op::Remove),
        (any::<usize>(), value).prop_map(|(i, v)| Op::Insert(i, v)),
        (any::<usize>(), value).prop_map(|(i, v)| Op::Text(i, v)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_edit_sequence_undoes_to_the_original_bytes(ops in prop::collection::vec(op(), 1..8)) {
        let mut d = doc();
        let mut applied = 0;
        for op in &ops {
            let r = d.edit("prop", |tx| {
                let all: Vec<_> = tx.root().descendants().collect();
                let pick = |i: usize| all[i % all.len()];
                match op {
                    Op::Set(i, k, v) => tx.set_attribute(pick(*i), k, v),
                    Op::Remove(i) => tx.remove(pick(*i)),
                    Op::Insert(i, v) => tx.insert(pick(*i), &NewElement::new("Private").attr("type", v.as_str())),
                    Op::Text(i, v) => tx.set_text(pick(*i), v),
                }
                Ok(())
            });
            prop_assert!(r.is_ok(), "{r:?}");
            if r.as_ref().is_ok_and(|n| *n > 0) {
                applied += 1;
            }
            prop_assert!(Document::parse(d.as_str()).is_ok());
            if let Op::Set(i, k, v) = op {
                let mut seen = None;
                let k = *k;
                d.edit("read", |tx| {
                    let all: Vec<_> = tx.root().descendants().collect();
                    seen = all[*i % all.len()].attribute(k).map(String::from);
                    Ok(())
                }).unwrap();
                prop_assert_eq!(seen.as_deref(), Some(v.as_str()), "the value reads back as written");
            }
        }
        prop_assert_eq!(d.history().len(), applied);
        while d.undo() {}
        prop_assert_eq!(d.as_str(), FIXTURE);
    }
}
