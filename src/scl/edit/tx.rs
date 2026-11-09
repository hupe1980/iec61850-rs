//! One transaction: a parse of the text, and the patches the edit issues against it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use roxmltree::Node;

use super::layout::{Layout, escape_attr, escape_text, indent_at, line_start_before};
use super::order::rank;
use super::patch::Patch;

/// An element of the document being edited.
///
/// A handle into one transaction's parse: it is valid for the duration of the
/// [`Document::edit`](super::Document::edit) closure that produced it.
#[derive(Clone, Copy, Debug)]
pub struct Element<'a>(Node<'a, 'a>);

impl<'a> Element<'a> {
    /// The local name (`IED`, `LN0`, …), without a namespace prefix.
    pub fn name(self) -> &'a str {
        self.0.tag_name().name()
    }

    /// An attribute without a namespace, by name, unescaped.
    pub fn attribute(self, name: &str) -> Option<&'a str> {
        self.0.attributes().find(|a| a.namespace().is_none() && a.name() == name).map(|a| a.value())
    }

    /// An attribute, or `""` when it is absent — the schema default for `prefix`, `lnInst` and
    /// most other naming attributes.
    pub fn attr_or_empty(self, name: &str) -> &'a str {
        self.attribute(name).unwrap_or("")
    }

    /// The element children, in document order.
    pub fn children(self) -> impl Iterator<Item = Element<'a>> + 'a {
        self.0.children().filter(Node::is_element).map(Element)
    }

    /// The element children with this local name.
    pub fn children_named(self, name: &'a str) -> impl Iterator<Item = Element<'a>> + 'a {
        self.children().filter(move |c| c.name() == name)
    }

    /// The first element child with this local name.
    pub fn child(self, name: &str) -> Option<Element<'a>> {
        self.children().find(|c| c.name() == name)
    }

    /// The parent element.
    pub fn parent(self) -> Option<Element<'a>> {
        self.0.parent_element().map(Element)
    }

    /// Every element below this one, in document order (not including itself).
    pub fn descendants(self) -> impl Iterator<Item = Element<'a>> + 'a {
        self.0.descendants().skip(1).filter(Node::is_element).map(Element)
    }

    /// The element's text content when it holds nothing but text, unescaped.
    pub fn text(self) -> Option<&'a str> {
        self.0.text()
    }

    /// The bytes the element occupies in the text, from `<` to its last `>`.
    pub fn range(self) -> Range<usize> {
        self.0.range()
    }

    fn same(&self, other: &Element<'_>) -> bool {
        self.0.id() == other.0.id()
    }
}

/// An element to insert, built in memory and written with the document's layout.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewElement {
    /// Local name; it takes the parent's namespace prefix.
    pub name: String,
    /// Attributes in the order they are written.
    pub attributes: Vec<(String, String)>,
    /// Child elements.
    pub children: Vec<NewElement>,
    /// Text content (written only when there are no children).
    pub text: Option<String>,
}

impl NewElement {
    /// An element with no attributes or content.
    pub fn new(name: impl Into<String>) -> NewElement {
        NewElement { name: name.into(), ..NewElement::default() }
    }

    /// Add an attribute.
    #[must_use]
    pub fn attr(mut self, name: impl Into<String>, value: impl Into<String>) -> NewElement {
        self.attributes.push((name.into(), value.into()));
        self
    }

    /// Add an attribute when `value` is non-empty — for the schema's `""`-default attributes.
    #[must_use]
    pub fn attr_if(self, name: impl Into<String>, value: &str) -> NewElement {
        if value.is_empty() { self } else { self.attr(name, value) }
    }

    /// Add a child element.
    #[must_use]
    pub fn child(mut self, child: NewElement) -> NewElement {
        self.children.push(child);
        self
    }

    /// Set the text content.
    #[must_use]
    pub fn text(mut self, text: impl Into<String>) -> NewElement {
        self.text = Some(text.into());
        self
    }

    fn write(&self, out: &mut String, prefix: &str, indent: &str, layout: &Layout) {
        out.push('<');
        out.push_str(prefix);
        out.push_str(&self.name);
        for (k, v) in &self.attributes {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&escape_attr(v, '"'));
            out.push('"');
        }
        if !self.children.is_empty() {
            out.push('>');
            let inner = format!("{indent}{}", layout.unit);
            for c in &self.children {
                out.push_str(layout.newline);
                out.push_str(&inner);
                c.write(out, prefix, &inner, layout);
            }
            out.push_str(layout.newline);
            out.push_str(indent);
            close(out, prefix, &self.name);
        } else if let Some(t) = &self.text {
            out.push('>');
            out.push_str(&escape_text(t));
            close(out, prefix, &self.name);
        } else {
            out.push_str("/>");
        }
    }
}

fn close(out: &mut String, prefix: &str, name: &str) {
    out.push_str("</");
    out.push_str(prefix);
    out.push_str(name);
    out.push('>');
}

/// One transaction against a document.
///
/// Every method records a patch against the text as it was when the transaction began; nothing
/// changes until the closure returns, and then all of it changes at once or none of it does.
pub struct Tx<'a> {
    text: &'a str,
    doc: &'a roxmltree::Document<'a>,
    layout: Layout,
    patches: Vec<Patch>,
}

impl<'a> Tx<'a> {
    pub(crate) fn new(text: &'a str, doc: &'a roxmltree::Document<'a>) -> Tx<'a> {
        Tx { text, doc, layout: Layout::infer(text, doc.root_element()), patches: Vec::new() }
    }

    pub(crate) fn into_patches(self) -> Vec<Patch> {
        self.patches
    }

    /// The root element (`SCL`).
    pub fn root(&self) -> Element<'a> {
        Element(self.doc.root_element())
    }

    /// Record a raw patch against the text as it was when the transaction began.
    pub fn patch(&mut self, patch: Patch) {
        self.patches.push(patch);
    }

    /// The text the transaction began with.
    pub fn text(&self) -> &'a str {
        self.text
    }

    /// Set an attribute, adding it after the last existing one if it is absent. The value is
    /// escaped for the quote character the attribute (or, when new, the element) already uses.
    pub fn set_attribute(&mut self, el: Element<'a>, name: &str, value: &str) {
        if let Some(a) = el.0.attributes().find(|a| a.namespace().is_none() && a.name() == name) {
            let v = a.range_value();
            let quote = self.quote_before(v.start);
            if a.value() != value {
                self.patches.push(Patch::replace(v, escape_attr(value, quote)));
            }
            return;
        }
        let quote = el.0.attributes().next().map_or('"', |a| self.quote_before(a.range_value().start));
        let at = el.0.attributes().next_back().map_or_else(|| self.qname_end(el), |a| a.range().end);
        self.patches.push(Patch::insert(at, format!(" {name}={quote}{}{quote}", escape_attr(value, quote))));
    }

    /// Remove an attribute and the whitespace before it. Absent is not an error.
    pub fn remove_attribute(&mut self, el: Element<'a>, name: &str) {
        if let Some(a) = el.0.attributes().find(|a| a.namespace().is_none() && a.name() == name) {
            let r = a.range();
            let start = self.text.get(..r.start).map_or(r.start, |b| b.trim_end_matches([' ', '\t', '\r', '\n']).len());
            self.patches.push(Patch::delete(start..r.end));
        }
    }

    /// Replace the element's content with text. An element with element children is refused
    /// silently (nothing is recorded), because its content is not text.
    pub fn set_text(&mut self, el: Element<'a>, text: &str) {
        if el.children().next().is_some() || el.text() == Some(text) {
            return;
        }
        let (open_end, self_closing) = self.start_tag_end(el);
        let escaped = escape_text(text);
        if self_closing {
            let slash = self.slash_before(open_end);
            let name = self.qname(el);
            self.patches.push(Patch::replace(slash..open_end + 1, format!(">{escaped}</{name}>")));
        } else {
            let close = self.end_tag_start(el);
            self.patches.push(Patch::replace(open_end + 1..close, escaped));
        }
    }

    /// Insert a child in the position the schema requires, indented like its siblings.
    pub fn insert(&mut self, parent: Element<'a>, child: &NewElement) {
        let layout = self.layout.clone();
        self.insert_with(parent, &child.name, |prefix, indent, out| child.write(out, prefix, indent, &layout));
    }

    /// Insert raw XML as a child of `parent`, at the position a child named `name` takes in the
    /// schema, after the siblings' indentation. The transaction is refused at commit if the
    /// result is not well-formed.
    pub fn insert_fragment(&mut self, parent: Element<'a>, name: &str, xml: &str) {
        self.insert_with(parent, name, |_, _, out| out.push_str(xml));
    }

    fn insert_with(&mut self, parent: Element<'a>, name: &str, render: impl FnOnce(&str, &str, &mut String)) {
        let prefix = self.prefix(parent);
        let siblings: Vec<Element<'a>> = parent.children().collect();
        let want = rank(parent.name(), name);
        let known = siblings.iter().rev().find(|s| {
            let r = rank(parent.name(), s.name());
            r != usize::MAX && r <= want
        });
        // An element the table does not know goes last.
        let after = if want == usize::MAX { siblings.last() } else { known };
        let parent_indent = indent_at(self.text, parent.range().start);
        let indent = siblings.first().map_or_else(|| format!("{parent_indent}{}", self.layout.unit), |s| String::from(indent_at(self.text, s.range().start)));
        let mut xml = String::new();
        xml.push_str(self.layout.newline);
        xml.push_str(&indent);
        render(&prefix, &indent, &mut xml);
        let (open_end, self_closing) = self.start_tag_end(parent);
        if let Some(s) = after {
            self.patches.push(Patch::insert(s.range().end, xml));
        } else if self_closing {
            let slash = self.slash_before(open_end);
            let name = self.qname(parent);
            self.patches.push(Patch::replace(slash..open_end + 1, format!(">{xml}{}{parent_indent}</{name}>", self.layout.newline)));
        } else {
            let close = self.end_tag_start(parent);
            let content = self.text.get(open_end + 1..close).unwrap_or("");
            if siblings.is_empty() && !content.contains('\n') {
                // `<P></P>` or `<P>text</P>`: put the closing tag on its own line.
                xml.push_str(self.layout.newline);
                xml.push_str(parent_indent);
            }
            self.patches.push(Patch::insert(open_end + 1, xml));
        }
    }

    /// Remove an element, and the line it stood on when nothing else was on it.
    pub fn remove(&mut self, el: Element<'a>) {
        let r = el.range();
        let start = line_start_before(self.text, r.start).unwrap_or(r.start);
        self.patches.push(Patch::delete(start..r.end));
    }

    /// Whether `a` and `b` are the same element.
    pub fn same(&self, a: Element<'_>, b: Element<'_>) -> bool {
        a.same(&b)
    }

    fn quote_before(&self, value_start: usize) -> char {
        match self.text.as_bytes().get(value_start.wrapping_sub(1)) {
            Some(b'\'') => '\'',
            _ => '"',
        }
    }

    fn qname(&self, el: Element<'a>) -> &'a str {
        let start = el.range().start + 1;
        self.text.get(start..self.qname_end(el)).unwrap_or("")
    }

    /// The parent's namespace prefix with its colon, so that new SCL elements share it.
    fn prefix(&self, el: Element<'a>) -> String {
        self.qname(el).rsplit_once(':').map_or_else(String::new, |(p, _)| format!("{p}:"))
    }

    fn qname_end(&self, el: Element<'a>) -> usize {
        let start = el.range().start + 1;
        let rest = self.text.get(start..).unwrap_or("");
        start + rest.find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>').unwrap_or(rest.len())
    }

    /// The offset of the `>` that ends the start tag, and whether the tag is self-closing.
    fn start_tag_end(&self, el: Element<'a>) -> (usize, bool) {
        let bytes = self.text.as_bytes();
        let mut i = self.qname_end(el);
        let mut quote: Option<u8> = None;
        while let Some(&b) = bytes.get(i) {
            match (quote, b) {
                (Some(q), b) if b == q => quote = None,
                (None, b'"' | b'\'') => quote = Some(b),
                (None, b'>') => return (i, bytes.get(i.wrapping_sub(1)) == Some(&b'/')),
                // Inside a quoted value, or any other byte of the tag.
                _ => {}
            }
            i += 1;
        }
        (el.range().end.saturating_sub(1), false)
    }

    /// The offset of the `/` of a self-closing tag's `/>`, with the whitespace before it.
    fn slash_before(&self, gt: usize) -> usize {
        let slash = gt.saturating_sub(1);
        self.text.get(..slash).map_or(slash, |b| b.trim_end_matches([' ', '\t', '\r', '\n']).len())
    }

    /// The offset of the `</` of the element's end tag.
    fn end_tag_start(&self, el: Element<'a>) -> usize {
        let r = el.range();
        self.text.get(r.clone()).and_then(|s| s.rfind("</")).map_or(r.end, |i| r.start + i)
    }
}
