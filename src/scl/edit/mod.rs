//! Editing SCL without reformatting it; see [`Document`].

mod layout;
mod ops;
mod order;
mod patch;
mod tx;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub use ops::{CbRef, ControlKind, ExtRefSource, Hitem, LnRef};
pub use patch::Patch;
pub use tx::{Element, NewElement, Tx};

use super::Scl;
use crate::common::{Error, Result};

/// One applied edit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    /// What the edit was, e.g. `rename IED Relay1 → Bay1Relay`.
    pub label: String,
    forward: Vec<Patch>,
    inverse: Vec<Patch>,
}

impl Transaction {
    /// The patches the edit applied, against the text before it.
    pub fn patches(&self) -> &[Patch] {
        &self.forward
    }
}

/// An SCL file being edited, without reformatting it.
///
/// The document holds the file's text, and the text *is* the document: an unedited document is
/// its input byte for byte, and an edit changes only the bytes it is about. Each edit is one
/// transaction — the text is parsed once, the edit records byte-range [`Patch`]es against that
/// parse, and they are applied together. A result that is not well-formed XML is refused and
/// the document is left as it was. Every applied transaction keeps its inverse, so
/// [`undo`](Document::undo) and [`redo`](Document::redo) restore exact bytes.
///
/// The typed operations ([`rename_ied`](Document::rename_ied),
/// [`set_gse_address`](Document::set_gse_address), …) keep references consistent; for anything
/// else, [`edit`](Document::edit) gives a [`Tx`] with raw element, attribute and text
/// operations. New elements go where the SCL schema requires them, indented like their
/// siblings, with the file's own line ending. A document with a DTD is refused, so no entity is
/// ever expanded or fetched.
///
/// ```
/// use iec61850_rs::scl::Document;
///
/// let mut doc = Document::parse(r#"<SCL><Header id="x"/>
///   <IED name="Relay1"/>
/// </SCL>"#)?;
/// doc.rename_ied("Relay1", "Bay1Relay")?;
/// assert!(doc.as_str().contains(r#"<IED name="Bay1Relay"/>"#));
/// doc.undo();
/// assert!(doc.as_str().contains(r#"<IED name="Relay1"/>"#));
/// # Ok::<(), iec61850_rs::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Document {
    text: String,
    undo: Vec<Transaction>,
    redo: Vec<Transaction>,
}

fn parse(text: &str) -> Result<roxmltree::Document<'_>> {
    roxmltree::Document::parse(text).map_err(|e| Error::Scl(format!("XML: {e}")))
}

impl Document {
    /// Take SCL text. It must be well-formed XML.
    pub fn parse(text: impl Into<String>) -> Result<Document> {
        let text = text.into();
        parse(&text)?;
        Ok(Document { text, undo: Vec::new(), redo: Vec::new() })
    }

    /// Take the bytes of an SCL file. They must be UTF-8; a byte-order mark is kept.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Document> {
        let text = String::from_utf8(bytes).map_err(|e| Error::Scl(format!("not UTF-8 (byte {})", e.utf8_error().valid_up_to())))?;
        Document::parse(text)
    }

    /// The current text — the input itself until an edit is applied.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The current text.
    pub fn into_string(self) -> String {
        self.text
    }

    /// A read-only view of the current text, for loading models, resolving subscriptions and
    /// validating.
    pub fn scl(&self) -> Result<Scl<'_>> {
        Scl::parse(&self.text)
    }

    /// Look at the current text through the same [`Element`] API an edit uses, without
    /// starting a transaction.
    pub fn read<R>(&self, f: impl FnOnce(Element<'_>) -> R) -> Result<R> {
        let doc = parse(&self.text)?;
        Ok(f(Tx::new(&self.text, &doc).root()))
    }

    /// Run one transaction. `f` records changes against a parse of the current text; they are
    /// applied together when it returns `Ok`. Returns the number of patches applied (zero leaves
    /// no history entry).
    ///
    /// # Errors
    ///
    /// Whatever `f` returns; [`Error::Scl`] if two changes overlap or the result is not
    /// well-formed XML. On any error the document is unchanged.
    pub fn edit<F>(&mut self, label: &str, f: F) -> Result<usize>
    where
        F: FnOnce(&mut Tx<'_>) -> Result<()>,
    {
        let patches = {
            let doc = parse(&self.text)?;
            let mut tx = Tx::new(&self.text, &doc);
            f(&mut tx)?;
            tx.into_patches()
        };
        let patches = patch::normalise(patches)?;
        if patches.is_empty() {
            return Ok(0);
        }
        let (text, inverse) = patch::apply(&self.text, &patches)?;
        parse(&text).map_err(|e| Error::Scl(format!("the edit would leave the document malformed: {e}")))?;
        let n = patches.len();
        self.text = text;
        self.undo.push(Transaction { label: String::from(label), forward: patches, inverse });
        self.redo.clear();
        Ok(n)
    }

    /// Undo the last transaction. Returns `false` when there is nothing to undo.
    pub fn undo(&mut self) -> bool {
        let Some(t) = self.undo.pop() else { return false };
        // The inverse was computed against exactly this text, so it always applies; the
        // fallback keeps the document unchanged if that invariant were ever broken.
        if let Ok((text, _)) = patch::apply(&self.text, &t.inverse) {
            self.text = text;
            self.redo.push(t);
            true
        } else {
            self.undo.push(t);
            false
        }
    }

    /// Redo the last undone transaction. Returns `false` when there is nothing to redo.
    pub fn redo(&mut self) -> bool {
        let Some(t) = self.redo.pop() else { return false };
        if let Ok((text, _)) = patch::apply(&self.text, &t.forward) {
            self.text = text;
            self.undo.push(t);
            true
        } else {
            self.redo.push(t);
            false
        }
    }

    /// The applied transactions, oldest first.
    pub fn history(&self) -> &[Transaction] {
        &self.undo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCL: &str = "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\">\n  <Header id='h'/>\n  <IED name=\"A\" desc='it&apos;s'>\n    <AccessPoint name=\"AP1\"/>\n  </IED>\n</SCL>\n";

    #[test]
    fn untouched_is_identical() {
        assert_eq!(Document::parse(SCL).map(Document::into_string).ok().as_deref(), Some(SCL));
    }

    #[test]
    fn malformed_input_and_output_are_refused() {
        assert!(Document::parse("<SCL>").is_err());
        assert!(Document::from_bytes(vec![0x3c, 0xff, 0x3e]).is_err());
        let mut d = Document::parse(SCL).ok();
        let r = d.as_mut().map(|d| {
            d.edit("bad", |tx| {
                let root = tx.root();
                tx.insert_fragment(root, "IED", "<IED name='B'>");
                Ok(())
            })
        });
        assert!(matches!(r, Some(Err(Error::Scl(_)))));
        assert_eq!(d.map(Document::into_string).as_deref(), Some(SCL));
    }

    #[test]
    fn attributes_keep_their_quotes_and_new_ones_follow_the_element() {
        let mut d = Document::parse(SCL).ok();
        let n = d.as_mut().map(|d| {
            d.edit("x", |tx| {
                let ied = tx.root().child("IED").ok_or(Error::NotFound("IED"))?;
                tx.set_attribute(ied, "desc", "a'b");
                tx.set_attribute(ied, "type", "X&Y");
                let h = tx.root().child("Header").ok_or(Error::NotFound("Header"))?;
                tx.set_attribute(h, "version", "2");
                Ok(())
            })
        });
        assert_eq!(n.and_then(Result::ok), Some(3));
        let text = d.map(Document::into_string).unwrap_or_default();
        // A new attribute takes the quote of the element's first attribute.
        assert!(text.contains("<IED name=\"A\" desc='a&apos;b' type=\"X&amp;Y\">"), "{text}");
        assert!(text.contains("<Header id='h' version='2'/>"), "{text}");
    }

    #[test]
    fn inserts_respect_schema_order_and_layout() {
        let mut d = Document::parse(SCL).ok();
        let r = d.as_mut().map(|d| {
            d.edit("x", |tx| {
                let root = tx.root();
                tx.insert(root, &NewElement::new("Communication").child(NewElement::new("SubNetwork").attr("name", "S1")));
                let ied = root.child("IED").ok_or(Error::NotFound("IED"))?;
                let ap = ied.child("AccessPoint").ok_or(Error::NotFound("AP"))?;
                tx.insert(ap, &NewElement::new("Server"));
                Ok(())
            })
        });
        assert!(matches!(r, Some(Ok(2))));
        let text = d.map(Document::into_string).unwrap_or_default();
        let want = "<Header id='h'/>\n  <Communication>\n    <SubNetwork name=\"S1\"/>\n  </Communication>\n  <IED";
        assert!(text.contains(want), "{text}");
        assert!(text.contains("<AccessPoint name=\"AP1\">\n      <Server/>\n    </AccessPoint>"), "{text}");
    }

    #[test]
    fn removal_takes_the_line_and_undo_redo_are_exact() {
        let mut d = Document::parse(SCL).ok();
        let Some(doc) = d.as_mut() else { return };
        let r = doc.edit("rm", |tx| {
            let ied = tx.root().child("IED").ok_or(Error::NotFound("IED"))?;
            tx.remove(ied);
            Ok(())
        });
        assert!(r.is_ok());
        assert_eq!(doc.as_str(), "<SCL xmlns=\"http://www.iec.ch/61850/2003/SCL\">\n  <Header id='h'/>\n</SCL>\n");
        let after = String::from(doc.as_str());
        assert!(doc.undo());
        assert_eq!(doc.as_str(), SCL);
        assert!(doc.redo());
        assert_eq!(doc.as_str(), after);
        assert!(!doc.redo());
    }

    #[test]
    fn text_content_is_set_and_self_closing_tags_are_opened() {
        let mut d = Document::parse("<SCL><P type='IP'/><Q>old</Q></SCL>").ok();
        let r = d.as_mut().map(|d| {
            d.edit("t", |tx| {
                let p = tx.root().child("P").ok_or(Error::NotFound("P"))?;
                tx.set_text(p, "10.0.0.1");
                let q = tx.root().child("Q").ok_or(Error::NotFound("Q"))?;
                tx.set_text(q, "a<b");
                Ok(())
            })
        });
        assert!(matches!(r, Some(Ok(2))));
        assert_eq!(d.map(Document::into_string).as_deref(), Some("<SCL><P type='IP'>10.0.0.1</P><Q>a&lt;b</Q></SCL>"));
    }
}
