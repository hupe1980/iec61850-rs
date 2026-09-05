//! Every `OpenSCD` fixture in `specs/fixtures/openscd/` loads leniently (all IEDs), the
//! dangling type references those files carry come back as diagnostics with stable codes,
//! strict loading rejects exactly those files, and every GOOSE control block with an
//! address yields a publisher configuration. Skips when `specs/` is absent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use iec61850_rs::common::Edition;
use iec61850_rs::model::{DiagnosticCode, IedModel};
use iec61850_rs::proto::ethernet::MacAddr;
use iec61850_rs::scl::{self, FindingCode, LoadOptions};

#[test]
fn openscd_fixtures_load() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    if !dir.is_dir() {
        return;
    }
    let (mut files, mut ieds, mut gcbs, mut diags, mut strict_failures) = (0, 0, 0, 0, 0);
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        files += 1;
        let version = scl::scl_version(&xml).unwrap();
        assert!(["2003", "2007B", "2007B4"].contains(&version.as_str()), "{}: {version}", path.display());
        for name in scl::ied_names(&xml).unwrap() {
            let model = IedModel::from_scl(&xml, Some(&name)).unwrap_or_else(|e| panic!("{}: IED {name}: {e}", path.display()));
            assert_eq!(model.name, name);
            ieds += 1;
            let strict = IedModel::from_scl_with(&xml, Some(&name), LoadOptions { strict: true });
            assert_eq!(strict.is_err(), !model.diagnostics.is_empty(), "{}: strict must fail iff lenient reported something", path.display());
            if let Err(e) = &strict {
                strict_failures += 1;
                assert!(e.to_string().contains(" at "), "{}: unhelpful: {e}", path.display());
            }
            for d in &model.diagnostics {
                diags += 1;
                assert!(d.at.starts_with(&name) || d.at.starts_with("Communication"), "{}: {d}", path.display());
                assert!(
                    matches!(
                        d.code,
                        DiagnosticCode::MissingLNodeType
                            | DiagnosticCode::MissingDOType
                            | DiagnosticCode::MissingDAType
                            | DiagnosticCode::BadAddress
                            | DiagnosticCode::MissingAttribute
                    ),
                    "{}: unexpected {d}",
                    path.display()
                );
            }
            for ld in &model.logical_devices {
                for ln in &ld.logical_nodes {
                    for gcb in &ln.gse_controls {
                        if gcb.address.is_some() && gcb.dat_set.is_some() {
                            let r = format!("{}/{}.{}", ld.name, ln.name, gcb.name);
                            model.goose_publisher_config(&r, MacAddr::default()).unwrap_or_else(|e| panic!("{r}: {e}"));
                            gcbs += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(files >= 4, "expected the OpenSCD fixtures, found {files}");
    assert!(ieds > 0 && diags > 0 && strict_failures > 0, "the corpus is known to contain dangling type references");
    eprintln!("openscd fixtures: {files} files, {ieds} IEDs, {gcbs} addressed GOOSE control blocks, {diags} diagnostics, {strict_failures} strict failures");
}

#[test]
fn every_data_set_member_of_the_corpus_resolves() {
    // The check that caught a real bug: `fcda_attribute` looked the first path component up
    // *inside* a `find` predicate, so it matched only when the data object happened to be
    // the first one declared — and it ignored the FCDA's own `ldInst`, so a data set
    // gathering members from a second logical device resolved to nothing. Both showed up
    // here as a wall of `UnresolvedFcda` against files whose types are perfectly well
    // defined, and neither showed up in a hand-written fixture.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    if !dir.is_dir() {
        return;
    }
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        for name in scl::ied_names(&xml).unwrap() {
            let model = IedModel::from_scl(&xml, Some(&name)).unwrap();
            // Only IEDs whose own types all resolved can be held to this: a file that never
            // defined an `LNodeType` cannot resolve the members that reference it.
            if model.diagnostics.iter().any(|d| d.code != DiagnosticCode::BadAddress) {
                continue;
            }
            for ld in &model.logical_devices {
                for ln in &ld.logical_nodes {
                    for ds in &ln.data_sets {
                        for m in ds.members.iter().filter(|m| m.da_name.is_some()) {
                            assert!(
                                model.fcda_attribute(&ld.name, m).is_some(),
                                "{}: {}/{}.{} member {} does not resolve",
                                path.display(),
                                ld.name,
                                ln.name,
                                ds.name,
                                m.mms_reference(&ld.name)
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 0, "the corpus should hold data sets with attribute members");
    eprintln!("openscd fixtures: {checked} data-set members resolved");
}

#[test]
fn the_corpus_validates_with_the_findings_it_is_known_to_have() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    let file = dir.join("valid2007B4.scd");
    if !file.is_file() {
        return;
    }
    let xml = std::fs::read_to_string(&file).unwrap();
    let report = scl::validate(&xml, 50, Edition::Ed2_1).unwrap();
    let codes: Vec<FindingCode> = report.findings.iter().map(|f| f.code).collect();
    assert!(!report.is_ok(), "this file is known to be incomplete");
    // What is actually wrong with it, and nothing else. `UnresolvedFcda` in particular must
    // not appear: every data-set member of this file does resolve.
    assert!(!codes.contains(&FindingCode::UnresolvedFcda), "{report:#?}");
    assert!(!codes.contains(&FindingCode::DuplicateStream), "{report:#?}");
    assert!(codes.contains(&FindingCode::MissingDataSet), "a GSEControl here has no datSet: {codes:?}");
    assert!(codes.contains(&FindingCode::Loader(DiagnosticCode::MissingLNodeType)), "{codes:?}");
    // IED2's control block has no `GSE` address, so IED1's inputs bound to it cannot be
    // subscribed — which is the finding a commissioning engineer needs.
    assert!(codes.contains(&FindingCode::UnresolvedSubscription), "{codes:?}");
}

#[test]
fn the_parsed_handle_answers_exactly_what_the_one_shot_functions_do() {
    // `Scl` exists so that a station file is parsed once instead of once per question.
    // It is only worth having if it cannot drift from the functions it replaces, so
    // the corpus is the check: same names, same version, same models, same subscriptions,
    // same findings.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    if !dir.is_dir() {
        return;
    }
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        let scl = scl::Scl::parse(&xml).unwrap();
        assert_eq!(scl.ied_names(), scl::ied_names(&xml).unwrap(), "{}", path.display());
        assert_eq!(scl.version(), scl::scl_version(&xml).unwrap(), "{}", path.display());
        for name in scl.ied_names() {
            assert_eq!(scl.model(Some(&name)).unwrap(), IedModel::from_scl(&xml, Some(&name)).unwrap(), "{}: {name}", path.display());
            assert_eq!(scl.subscriptions(&name, 50).unwrap(), scl::subscriptions(&xml, &name, 50).unwrap(), "{}: {name}", path.display());
        }
        assert_eq!(scl.models().unwrap().len(), scl.ied_names().len());
        assert_eq!(scl.validate(50, Edition::Ed2_1).unwrap(), scl::validate(&xml, 50, Edition::Ed2_1).unwrap(), "{}", path.display());
        files += 1;
    }
    assert!(files >= 4, "expected the OpenSCD fixtures, found {files}");
}

#[test]
fn every_sampled_value_stream_in_the_corpus_describes_its_channels() {
    // The dataset-driven layout against real files rather than a fixture: every
    // addressed sampled-value control block whose data set resolves must produce a layout
    // whose length is the ASDU length the publisher configuration computes independently.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    if !dir.is_dir() {
        return;
    }
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "scd") {
            continue;
        }
        let xml = std::fs::read_to_string(&path).unwrap();
        let scl = scl::Scl::parse(&xml).unwrap();
        for name in scl.ied_names() {
            let model = scl.model(Some(&name)).unwrap();
            for ld in &model.logical_devices {
                for ln in &ld.logical_nodes {
                    for cb in ln.smv_controls.iter().filter(|c| c.address.is_some()) {
                        let reference = format!("{}/{}.{}", ld.name, ln.name, cb.name);
                        let Ok(pubcfg) = model.sv_publisher_config(&reference, MacAddr::default(), 50) else { continue };
                        let stream = model.sv_stream_config(&reference, 50).unwrap();
                        let layout = stream.layout.unwrap_or_else(|| panic!("{reference}: publishable but no layout"));
                        assert_eq!(layout.len(), pubcfg.profile.sample_len, "{reference}: the layout and the summed ASDU length disagree");
                        assert_eq!(layout.channels().len(), model.data_set(ln, cb.dat_set.as_deref().unwrap()).unwrap().members.len());
                        checked += 1;
                    }
                }
            }
        }
    }
    eprintln!("openscd fixtures: {checked} addressed sampled-value streams with a channel layout");
}

#[test]
fn subscriptions_resolve_signal_bound_ext_refs_in_the_corpus() {
    // Only one of the seven `ExtRef`s in this file carries `srcCBName`. The rest name the
    // signal and leave the tool to find the control block that publishes it, which is what
    // a real SCD looks like.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("specs/fixtures/openscd");
    let file = dir.join("valid2007B4.scd");
    if !file.is_file() {
        return;
    }
    let xml = std::fs::read_to_string(&file).unwrap();
    let subs = scl::subscriptions(&xml, "IED2", 50).unwrap();
    assert_eq!(subs.goose.len(), 1, "{subs:#?}");
    let g = &subs.goose[0];
    assert_eq!(g.publisher, "IED1");
    assert_eq!(g.identifier, "IED1CircuitBreaker_CB1/LLN0$GO$GCB");
    assert_eq!(g.appid, 0x0010);
    assert_eq!(g.ext_refs.len(), 4, "four signals, all on the one control block that publishes them");
    assert!(g.ext_refs.iter().all(|x| x.src_cb_name.is_none()), "these are the signal-bound ones");
    assert!(subs.unresolved.is_empty(), "{:#?}", subs.unresolved);
}
