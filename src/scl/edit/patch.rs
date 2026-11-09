//! Byte-range patches: the only way the text of a [`Document`](super::Document) changes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use crate::common::{Error, Result};

/// One change to the text: replace `range` with `text`.
///
/// An empty `range` inserts; an empty `text` deletes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    /// The bytes replaced, in the text the patch applies to.
    pub range: Range<usize>,
    /// What replaces them.
    pub text: String,
}

impl Patch {
    /// Replace `range` with `text`.
    pub fn replace(range: Range<usize>, text: impl Into<String>) -> Patch {
        Patch { range, text: text.into() }
    }

    /// Insert `text` at `at`.
    pub fn insert(at: usize, text: impl Into<String>) -> Patch {
        Patch { range: at..at, text: text.into() }
    }

    /// Delete `range`.
    pub fn delete(range: Range<usize>) -> Patch {
        Patch { range, text: String::new() }
    }

    fn is_deletion(&self) -> bool {
        self.text.is_empty() && !self.range.is_empty()
    }

    /// `other` lies wholly inside this deletion. An insertion at either edge is outside it.
    fn swallows(&self, other: &Patch) -> bool {
        self.is_deletion()
            && other.range.start >= self.range.start
            && other.range.end <= self.range.end
            && !(other.range.is_empty() && (other.range.start == self.range.start || other.range.start == self.range.end))
    }
}

/// Put patches in application order and resolve the one legitimate kind of overlap.
///
/// Patches are sorted by position, insertions at one offset keeping the order they were issued
/// in. A patch wholly inside a deletion is dropped, because removing an element subsumes every
/// edit inside it. Any other overlap is an error: two operations disagree about the same bytes.
pub(crate) fn normalise(patches: Vec<Patch>) -> Result<Vec<Patch>> {
    let mut indexed: Vec<(usize, Patch)> = patches.into_iter().enumerate().collect();
    indexed.sort_by_key(|(i, p)| (p.range.start, p.range.end, *i));
    let mut out: Vec<Patch> = Vec::with_capacity(indexed.len());
    for (_, p) in indexed {
        if p.is_deletion() {
            while out.last().is_some_and(|q| p.swallows(q)) {
                out.pop();
            }
        }
        if let Some(last) = out.last() {
            if last.swallows(&p) {
                continue;
            }
            if p.range.start < last.range.end {
                return Err(Error::Scl(format!("overlapping edits at bytes {:?} and {:?}", last.range, p.range)));
            }
        }
        out.push(p);
    }
    Ok(out)
}

/// Apply normalised patches to `text`, returning the new text and the patches that undo them.
///
/// The inverse patches are expressed against the new text, so applying them to it restores
/// `text` exactly.
pub(crate) fn apply(text: &str, patches: &[Patch]) -> Result<(String, Vec<Patch>)> {
    let mut out = String::with_capacity(text.len());
    let mut inverse = Vec::with_capacity(patches.len());
    let mut at = 0;
    for p in patches {
        let (Some(keep), Some(old)) = (text.get(at..p.range.start), text.get(p.range.clone())) else {
            return Err(Error::Scl(format!("edit at bytes {:?} is outside the text or splits a character", p.range)));
        };
        out.push_str(keep);
        let start = out.len();
        out.push_str(&p.text);
        inverse.push(Patch::replace(start..out.len(), old));
        at = p.range.end;
    }
    let Some(rest) = text.get(at..) else {
        return Err(Error::Scl(String::from("edit past the end of the text")));
    };
    out.push_str(rest);
    Ok((out, inverse))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(text: &str, patches: Vec<Patch>) -> Result<String> {
        let p = normalise(patches)?;
        let (out, inv) = apply(text, &p)?;
        let (back, _) = apply(&out, &inv)?;
        assert_eq!(back, text, "the inverse restores the original");
        Ok(out)
    }

    #[test]
    fn inserts_at_one_offset_keep_their_order() {
        assert_eq!(run("ab", vec![Patch::insert(1, "x"), Patch::insert(1, "y")]).ok().as_deref(), Some("axyb"));
    }

    #[test]
    fn replacements_apply_regardless_of_issue_order() {
        assert_eq!(run("abcdef", vec![Patch::replace(4..5, "E"), Patch::replace(0..1, "A")]).ok().as_deref(), Some("AbcdEf"));
    }

    #[test]
    fn a_patch_inside_a_deletion_is_dropped_either_way_round() {
        assert_eq!(run("0123456789", vec![Patch::replace(3..4, "x"), Patch::delete(2..6)]).ok().as_deref(), Some("016789"));
        assert_eq!(run("0123456789", vec![Patch::delete(2..6), Patch::replace(3..4, "x")]).ok().as_deref(), Some("016789"));
    }

    #[test]
    fn an_insert_at_the_edge_of_a_deletion_survives() {
        assert_eq!(run("0123", vec![Patch::delete(1..3), Patch::insert(1, "a"), Patch::insert(3, "b")]).ok().as_deref(), Some("0ab3"));
    }

    #[test]
    fn other_overlaps_are_refused() {
        assert!(normalise(vec![Patch::replace(0..3, "x"), Patch::replace(2..4, "y")]).is_err());
        assert!(normalise(vec![Patch::replace(0..4, "x"), Patch::insert(2, "y")]).is_err());
    }

    #[test]
    fn a_patch_that_splits_a_character_is_refused() {
        assert!(apply("ä", &[Patch::replace(0..1, "a")]).is_err());
        assert!(apply("abc", &[Patch::replace(2..9, "a")]).is_err());
    }
}
