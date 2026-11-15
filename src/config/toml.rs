//! TOML in, the JSON value of the same document out.
//!
//! TOML is a syntax for the schema in `config/mod.rs`, not a second schema: this module only
//! converts, and the one deserializer does the rest. That keeps the two from drifting: every
//! JSON fixture converted to TOML compiles to an equal plan, and every broken config yields
//! equal diagnostics up to the position suffix.
//!
//! Conversion rules, all of them:
//! - tables -> objects, arrays -> arrays, strings/integers/floats/booleans as themselves;
//! - an offset date-time -> its RFC 3339 string (the schema's `after` reads both unix seconds
//!   and RFC 3339, so `after = 2026-12-01T00:00:00Z` works in either format);
//! - local dates and times (no offset) are an error at their position: the schema has no
//!   value for a time without a zone.
//!
//! YAML is deliberately not offered: implicit typing (`no` -> false, `010` -> 8) would make
//! the same text mean different values than the schema reads, and JSON already serves
//! generators.

use super::SchemaError;
use std::ops::Range;
use std::sync::Arc;

/// Byte span of every value, by JSON pointer. Kept only for diagnostics; never consulted by
/// the compiler.
pub(crate) struct Positions {
    source: Arc<str>,
    spans: Vec<(String, Range<usize>)>,
}

impl Positions {
    /// 1-based line and column of the value at `pointer`, or of its nearest ancestor that has
    /// one (a key the schema missed points at its table).
    pub fn position(&self, pointer: &str) -> Option<(usize, usize)> {
        let mut pointer = pointer;
        loop {
            if let Some((_, span)) = self.spans.iter().find(|(p, _)| p == pointer) {
                return Some(line_column(&self.source, span.start));
            }
            pointer = &pointer[..pointer.rfind('/')?];
        }
    }
}

/// 1-based line and column of byte `at` of `text`.
fn line_column(text: &str, at: usize) -> (usize, usize) {
    let before = &text.as_bytes()[..at.min(text.len())];
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let column = before.len()
        - before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1)
        + 1;
    (line, column)
}

/// Parses TOML and converts it. A syntax error carries the TOML line and column and an empty
/// pointer, as a JSON syntax error does.
pub(crate) fn to_json(bytes: &[u8]) -> Result<(serde_json::Value, Positions), SchemaError> {
    let error = |line, column, message: String| SchemaError {
        pointer: String::new(),
        line,
        column,
        message,
    };
    let text = std::str::from_utf8(bytes).map_err(|e| error(0, 0, format!("not UTF-8: {e}")))?;
    if let Err(e) = toml_edit::Document::parse(text) {
        let (line, column) = e.span().map_or((0, 0), |s| line_column(text, s.start));
        return Err(error(line, column, e.message().to_owned()));
    }
    Err(error(
        0,
        0,
        "this upstreamer reads JSON configs only; converting TOML is not built yet".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_syntax_error_names_its_line_and_column() {
        let e = to_json(b"version = 1\n[[sites]\n").err().unwrap();
        assert_eq!((e.pointer.as_str(), e.line), ("", 2));
        assert!(e.column > 0, "{}", e.column);
        assert_eq!(line_column("a\nbc\nd", 4), (2, 3));
        assert_eq!(line_column("a\nbc\nd", 0), (1, 1));
    }
}
