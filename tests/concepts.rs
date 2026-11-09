//! The internal architecture notes, checked for the mistakes prose cannot make loudly.
//!
//! `concepts/` is git-ignored — internal, not published — so this test **skips when the
//! directory is absent**, which is what CI and every consumer of the crate see. It runs on
//! the machine that has the notes, the only machine that can break them.
//!
//! Checks: `D`/`R` identifiers are numbered contiguously from 1, every citation resolves,
//! every relative link between the documents resolves, the counts the prose states agree
//! with the entries there are, and every open roadmap item names exactly one feature
//! specification under `specs/` while every specification there is named by exactly one item.
//!
//! One check needs no notes and so is the one CI sees: nothing published — `src/`, `tests/`,
//! `examples/`, the fuzz targets, the site, the README, the changelog, `Cargo.toml` — cites `concepts/`, `specs/` or `.specify/`, because a
//! reader of the crate cannot open any of them (D54).

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

/// The roadmap is the spec of specs: an open item is a `` ### `#anchor` `` heading naming one
/// folder on a `**Specified as:**` line, and a folder under `specs/` that no item names is work
/// nobody has scheduled. `specs/archive/` holds the shipped, superseded and refused.
#[test]
fn every_roadmap_item_names_its_specification() {
    let Some(dir) = concepts() else { return };
    let specs = Path::new(env!("CARGO_MANIFEST_DIR")).join("specs");
    if !specs.is_dir() {
        return;
    }
    let roadmap = fs::read_to_string(dir.join("ROADMAP.md")).expect("read ROADMAP.md");

    let items = roadmap.lines().filter(|l| l.starts_with("### `#")).count();
    let named: Vec<&str> = roadmap.lines().filter_map(|l| l.strip_prefix("**Specified as:** `")?.split('`').next()).collect();
    assert_eq!(items, named.len(), "ROADMAP.md: {items} items but {} **Specified as:** lines", named.len());

    let unique: BTreeSet<&str> = named.iter().copied().collect();
    assert_eq!(unique.len(), named.len(), "ROADMAP.md names a specification twice: {named:?}");

    let missing: Vec<_> = unique.iter().filter(|s| !specs.join(s).join("spec.md").is_file()).collect();
    assert!(missing.is_empty(), "ROADMAP.md names specifications that do not exist: {missing:?}");

    let orphans: Vec<_> = fs::read_dir(&specs)
        .expect("read specs/")
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.as_bytes().first().is_some_and(u8::is_ascii_digit))
        .filter(|name| !unique.contains(name.as_str()))
        .collect();
    assert!(orphans.is_empty(), "specs/ holds specifications no roadmap item names: {orphans:?}");
}

/// The published tree stands on its own. A path into the internal notes, the specifications or
/// the Spec Kit machinery renders as a reference and leads nowhere for every reader who is not
/// a maintainer.
#[test]
fn nothing_published_cites_the_internal_tree() {
    fn walk(path: &Path, out: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).expect("read dir").flatten() {
                walk(&entry.path(), out);
            }
        } else if path.extension().is_some_and(|e| e == "rs" || e == "md" || e == "toml") {
            out.push(path.to_path_buf());
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for published in ["src", "examples", "tests", "fuzz/fuzz_targets", "site/content", "README.md", "CHANGELOG.md", "Cargo.toml"] {
        walk(&root.join(published), &mut files);
    }
    // This file is the guard, and has to name what it guards.
    files.retain(|f| !f.ends_with("tests/concepts.rs"));

    let mut leaks = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read published file");
        for (n, line) in text.lines().enumerate() {
            let cites = ["concepts/", "specs/", ".specify/"].iter().any(|internal| {
                line.match_indices(internal).any(|(at, _)| {
                    // `specs/` as a path, not the tail of `nsd-specs/` or `.specify/`'s `specify/`.
                    !line[..at].chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                })
            });
            // A decision or risk id (`D12`, `R2`) points into the same notes, just without a path.
            // `R2-1` (the 9-2LE guideline's revision) is a version, not an id.
            let bytes = line.as_bytes();
            let cites_id = line.match_indices(['D', 'R']).any(|(at, _)| {
                let before = at.checked_sub(1).and_then(|i| bytes.get(i)).copied();
                let digits = bytes[at + 1..].iter().take_while(|b| b.is_ascii_digit()).count();
                let after = bytes.get(at + 1 + digits).copied();
                (1..=2).contains(&digits)
                    && !before.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
                    && !after.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            });
            // Spec Kit requirement ids (`SR-004`, `FR-012`, `SC-003`) point into the same specs.
            let cites_spec_id = ["SR-", "FR-", "SC-"].iter().any(|prefix| {
                line.match_indices(prefix).any(|(at, _)| {
                    let digits = bytes[at + 3..].iter().take_while(|b| b.is_ascii_digit()).count();
                    digits == 3 && !at.checked_sub(1).and_then(|i| bytes.get(i)).is_some_and(u8::is_ascii_alphanumeric)
                })
            });
            if cites || cites_id || cites_spec_id {
                let file = file.strip_prefix(root).unwrap_or(file).display();
                leaks.push(format!("{file}:{}", n + 1));
            }
        }
    }
    assert!(leaks.is_empty(), "published files cite a path their reader does not have: {leaks:?}");
}
