//! The internal architecture notes, checked for the mistakes prose cannot make loudly.
//!
//! `concepts/` is git-ignored — internal, not published — so this test **skips when the
//! directory is absent**, which is what CI and every consumer of the crate see. It runs on
//! the machine that has the notes, the only machine that can break them.
//!
//! Checks: `D`/`R` identifiers are numbered contiguously from 1, every citation resolves,
//! every relative link between the documents resolves, the counts the prose states agree
//! with the entries there are.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn concepts() -> Option<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("concepts");
    dir.is_dir().then_some(dir)
}

fn pages(dir: &Path) -> Vec<(String, String)> {
    let mut out: Vec<_> = fs::read_dir(dir)
        .expect("read concepts/")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .map(|p| (p.file_name().expect("name").to_string_lossy().into_owned(), fs::read_to_string(&p).expect("read page")))
        .collect();
    out.sort();
    assert!(!out.is_empty(), "concepts/ exists but holds no documents");
    out
}

/// Identifiers defined at the start of a line as `**D12 —`.
fn defined(text: &str, letter: char) -> BTreeSet<u32> {
    text.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("**")?.strip_prefix(letter)?;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() || !rest[digits.len()..].starts_with(" —") {
                return None;
            }
            digits.parse().ok()
        })
        .collect()
}

/// Identifiers cited anywhere as `D12` / `R3` (word-bounded).
fn cited(text: &str, letter: char) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let bytes = text.as_bytes();
    for (i, _) in text.match_indices(letter) {
        let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
        if !prev_ok {
            continue;
        }
        let digits: String = text[i + 1..].chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            continue;
        }
        let after = text[i + 1 + digits.len()..].chars().next();
        if after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        if let Ok(n) = digits.parse() {
            out.insert(n);
        }
    }
    out
}

fn assert_contiguous(ids: &BTreeSet<u32>, what: &str) {
    let expected: BTreeSet<u32> = (1..=ids.len() as u32).collect();
    assert_eq!(*ids, expected, "{what} numbers must run contiguously from 1");
}

#[test]
fn identifiers_are_contiguous_and_cited_ones_exist() {
    let Some(dir) = concepts() else { return };
    let pages = pages(&dir);
    let text = |name: &str| pages.iter().find(|(n, _)| n == name).map_or_else(|| panic!("{name} missing"), |(_, t)| t.as_str());
    let d = defined(text("DECISIONS.md"), 'D');
    let r = defined(text("RISKS.md"), 'R');
    assert_contiguous(&d, "D");
    assert_contiguous(&r, "R");
    for (name, t) in &pages {
        for n in cited(t, 'D') {
            assert!(d.contains(&n), "{name} cites D{n}, which DECISIONS.md does not define");
        }
        for n in cited(t, 'R') {
            assert!(r.contains(&n), "{name} cites R{n}, which RISKS.md does not define");
        }
    }
}

#[test]
fn relative_links_resolve() {
    let Some(dir) = concepts() else { return };
    let pages = pages(&dir);
    let names: BTreeSet<&str> = pages.iter().map(|(n, _)| n.as_str()).collect();
    for (name, t) in &pages {
        for (i, _) in t.match_indices("](") {
            let rest = &t[i + 2..];
            let Some(end) = rest.find(')') else { continue };
            let target = &rest[..end];
            if target.starts_with("http") || target.starts_with('#') || target.starts_with("../") {
                continue;
            }
            let file = target.split('#').next().unwrap_or(target);
            assert!(names.contains(file), "{name} links to {target}, which does not exist");
        }
    }
}

/// The English for a count, capitalised, up to 99.
///
/// Generated rather than listed: a hard-coded table stops working the moment the notes gain
/// one more decision, which is exactly the drift this test exists to catch.
fn number_word(n: usize) -> String {
    const UNITS: [&str; 20] = [
        "Zero",
        "One",
        "Two",
        "Three",
        "Four",
        "Five",
        "Six",
        "Seven",
        "Eight",
        "Nine",
        "Ten",
        "Eleven",
        "Twelve",
        "Thirteen",
        "Fourteen",
        "Fifteen",
        "Sixteen",
        "Seventeen",
        "Eighteen",
        "Nineteen",
    ];
    const TENS: [&str; 10] = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];
    assert!(n < 100, "the notes have grown past what this test can spell: {n}");
    if n < 20 {
        return UNITS[n].to_string();
    }
    let (tens, unit) = (TENS[n / 10], n % 10);
    if unit == 0 { tens.to_string() } else { format!("{tens}-{}", UNITS[unit].to_lowercase()) }
}

#[test]
fn number_words_are_spelt_the_way_the_notes_spell_them() {
    assert_eq!(number_word(8), "Eight");
    assert_eq!(number_word(20), "Twenty");
    assert_eq!(number_word(26), "Twenty-six");
    assert_eq!(number_word(40), "Forty");
    assert_eq!(number_word(99), "Ninety-nine");
}

#[test]
fn stated_counts_match() {
    let Some(dir) = concepts() else { return };
    let pages = pages(&dir);
    for (file, letter) in [("DECISIONS.md", 'D'), ("RISKS.md", 'R')] {
        let t = pages.iter().find(|(n, _)| n == file).map(|(_, t)| t).expect(file);
        let n = defined(t, letter).len();
        let word = number_word(n);
        assert!(
            t.contains(&format!("{word} things")) || t.contains(&format!("{word} of them")),
            "{file}: the prose should state `{word} things …` or `{word} of them` for {n} entries"
        );
    }
}
