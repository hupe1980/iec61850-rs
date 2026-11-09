//! The SCL editing DOM on arbitrary input: no panic; an unedited document is its input; an
//! accepted edit leaves well-formed XML; undo restores the input exactly.
#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::scl::{Document, LnRef, NewElement};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The first bytes steer the edits; the rest is the document.
    let (ops, text) = data.split_at(data.len().min(8));
    let Ok(mut doc) = Document::from_bytes(text.to_vec()) else { return };
    assert_eq!(doc.as_str().as_bytes(), text, "an unedited document is its input");

    for (n, &op) in ops.iter().enumerate() {
        let value = format!("v{op}&<\"'\t{n}");
        let r = doc.edit("fuzz", |tx| {
            let all: Vec<_> = tx.root().descendants().collect();
            let el = all.get(usize::from(op) % all.len().max(1)).copied().unwrap_or(tx.root());
            match op % 5 {
                0 => tx.set_attribute(el, "name", &value),
                1 => tx.remove_attribute(el, "name"),
                2 if !all.is_empty() => tx.remove(el),
                3 => tx.insert(el, &NewElement::new("Private").attr("type", value.as_str())),
                _ => tx.set_text(el, &value),
            }
            Ok(())
        });
        if r.is_ok() {
            assert!(Document::parse(doc.as_str()).is_ok(), "an accepted edit leaves well-formed XML");
        }
    }
    // The typed operations must refuse or succeed, never panic.
    let _ = doc.rename_ied("A", "B");
    let _ = doc.remove_ln("A", "LD0", &LnRef::new("", "XCBR", "1"));
    let _ = doc.scl().map(|s| s.ied_names());

    while doc.undo() {}
    assert_eq!(doc.as_str().as_bytes(), text, "undo restores the input");
});
