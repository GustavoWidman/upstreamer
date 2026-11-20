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

mod convert;

use super::SchemaError;
use std::collections::HashMap;
use std::sync::Arc;

/// Where each value starts, by JSON pointer. Kept only for diagnostics; never consulted by the
/// compiler.
pub(crate) struct Positions {
    source: Arc<str>,
    starts: HashMap<String, usize>,
}

impl Positions {
    /// 1-based line and column of the value at `pointer`, or of its nearest ancestor that has
    /// one (a key the schema missed points at its table).
    pub fn position(&self, pointer: &str) -> Option<(usize, usize)> {
        let mut pointer = pointer;
        loop {
            if let Some(&start) = self.starts.get(pointer) {
                return Some(convert::line_column(&self.source, start));
            }
            pointer = &pointer[..pointer.rfind('/')?];
        }
    }
}

/// A JSON value as TOML text (what `upstreamer convert` prints, and what the tests write).
#[cfg(test)]
pub(crate) fn emit(value: &serde_json::Value) -> Result<String, String> {
    convert::emit(value)
}

/// A TOML document as JSON text, for `upstreamer convert`. A syntax error names its line and
/// column.
pub fn toml_to_json(text: &str) -> Result<String, String> {
    match convert::parse(text) {
        Ok(converted) => Ok(convert::emit_json(&converted.value)),
        Err(convert::Failure { offset, message }) => Err(match offset {
            Some(at) => {
                let (line, column) = convert::line_column(text, at);
                format!("{message} (line {line}, column {column})")
            }
            None => message,
        }),
    }
}

/// A JSON document as TOML text, for `upstreamer convert`.
pub fn json_to_toml(text: &str) -> Result<String, String> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    convert::emit(&value)
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
    match convert::parse(text) {
        Ok(convert::Converted { value, starts }) => {
            let positions = Positions {
                source: Arc::from(text),
                starts,
            };
            Ok((value, positions))
        }
        Err(convert::Failure { offset, message }) => {
            let (line, column) = offset.map_or((0, 0), |at| convert::line_column(text, at));
            Err(error(line, column, message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_syntax_error_names_its_line_and_column() {
        let e = to_json(b"version = 1\n[[sites]\n").err().unwrap();
        assert_eq!((e.pointer.as_str(), e.line), ("", 2));
        assert!(e.column > 0, "{}", e.column);
    }

    #[test]
    fn a_missing_key_points_at_its_table() {
        let (_, positions) = to_json(b"version = 1\n[[sites]]\nname = 'a'\n").unwrap();
        assert_eq!(positions.position("/sites/0/hosts"), Some((2, 1)));
        assert_eq!(positions.position("/version"), Some((1, 11)));
        assert_eq!(positions.position("/nope"), None);
    }

    #[test]
    fn a_local_time_is_reported_at_its_position() {
        let e = to_json(b"version = 1\nafter = 2026-12-01\n").err().unwrap();
        assert_eq!((e.line, e.column), (2, 9));
        assert!(e.message.contains("no time zone"), "{}", e.message);
    }
}
