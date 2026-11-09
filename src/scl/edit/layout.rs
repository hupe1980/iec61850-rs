//! How the document is laid out — line ending, indentation — and how values are escaped.

use alloc::string::String;

/// The document's own formatting conventions, inferred once per transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// `"\r\n"` if the document uses it anywhere, else `"\n"`.
    pub newline: &'static str,
    /// One level of indentation.
    pub unit: String,
}

impl Layout {
    pub(crate) fn infer(text: &str, root: roxmltree::Node<'_, '_>) -> Layout {
        let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let parent = indent_at(text, root.range().start);
        let unit = root
            .children()
            .find(roxmltree::Node::is_element)
            .map(|c| indent_at(text, c.range().start))
            .and_then(|child| child.strip_prefix(parent).filter(|u| !u.is_empty()).map(String::from))
            .unwrap_or_else(|| String::from("  "));
        Layout { newline, unit }
    }
}

/// The whitespace between the line start and `at`, or `""` if anything else is on that line
/// before `at`.
pub(crate) fn indent_at(text: &str, at: usize) -> &str {
    let Some(before) = text.get(..at) else { return "" };
    let line_start = before.rfind('\n').map_or(0, |i| i + 1);
    let indent = before.get(line_start..).unwrap_or("");
    if indent.bytes().all(|b| b == b' ' || b == b'\t') { indent } else { "" }
}

/// Where the line holding `at` begins, if only whitespace precedes `at` on it — including the
/// newline (and a `\r` before it) that ends the previous line. Removing from here to the end of
/// an element removes its line.
pub(crate) fn line_start_before(text: &str, at: usize) -> Option<usize> {
    let before = text.get(..at)?;
    let nl = before.rfind('\n')?;
    let gap = before.get(nl + 1..)?;
    if !gap.bytes().all(|b| b == b' ' || b == b'\t') {
        return None;
    }
    Some(if nl > 0 && before.as_bytes().get(nl - 1) == Some(&b'\r') { nl - 1 } else { nl })
}

/// Escape an attribute value for the quote character that delimits it. Tabs and line breaks are
/// written as character references, because a parser normalises them to spaces otherwise.
pub(crate) fn escape_attr(value: &str, quote: char) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' if quote == '"' => out.push_str("&quot;"),
            '\'' if quote == '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
    out
}

/// Escape character data. `>` is escaped so that `]]>` cannot appear.
pub(crate) fn escape_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#13;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_read_off_the_document() {
        let text = "<SCL>\r\n\t<Header/>\r\n</SCL>";
        let doc = roxmltree::Document::parse(text).ok();
        let l = doc.map(|d| Layout::infer(text, d.root_element()));
        assert_eq!(l, Some(Layout { newline: "\r\n", unit: String::from("\t") }));
    }

    #[test]
    fn indentation_needs_a_clean_line() {
        assert_eq!(indent_at("<a>\n    <b/>", 8), "    ");
        assert_eq!(indent_at("<a> <b/>", 4), "");
        assert_eq!(line_start_before("<a>\r\n  <b/>", 7), Some(3));
        assert_eq!(line_start_before("<a> <b/>", 4), None);
    }

    #[test]
    fn escaping_follows_the_quote() {
        assert_eq!(escape_attr("a\"b'c&<>\t", '"'), "a&quot;b'c&amp;&lt;>&#9;");
        assert_eq!(escape_attr("a\"b'c", '\''), "a\"b&apos;c");
        assert_eq!(escape_text("x]]>&<"), "x]]&gt;&amp;&lt;");
    }
}
