//! TOML to a JSON value, and back.
//!
//! This file depends on nothing in the crate: the library reads configs through it and the
//! `upstreamer` binary includes it for `upstreamer convert`, so both read TOML one way.
//!
//! Reading, all the rules:
//! - tables become objects, arrays arrays, strings, integers, floats and booleans themselves;
//! - an offset date-time becomes its RFC 3339 string (the schema's `after` reads unix seconds
//!   and RFC 3339 alike);
//! - a local date, local time or local date-time is an error at its position: the schema has no
//!   value for a time without a zone.
//!
//! Writing is the inverse. The one value TOML lacks is `null`. The schema reads `null` and an
//! absent key alike everywhere except in a header map, where `null` removes the header and
//! `false` says the same thing, so `null` is written as `false` inside `headers` and
//! `requestHeaders` and dropped everywhere else. A `null` in an array has no TOML spelling and
//! is an error.

use serde_json::{Map, Number, Value};
use std::collections::HashMap;
use std::fmt::Write as _;
use toml_edit::{Item, Table};

/// A parsed document: its JSON value and where each value sits in the text.
pub(crate) struct Converted {
    pub value: Value,
    /// Byte offset of the start of each value, by JSON pointer (RFC 6901). Tables reached
    /// only through dotted keys have the offset of their key.
    pub starts: HashMap<String, usize>,
}

/// Why a document did not convert: a message, and the byte offset it applies to when known.
pub(crate) struct Failure {
    pub offset: Option<usize>,
    pub message: String,
}

/// 1-based line and column of byte `at` of `text`.
pub(crate) fn line_column(text: &str, at: usize) -> (usize, usize) {
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

pub(crate) fn parse(text: &str) -> Result<Converted, Failure> {
    let document = toml_edit::Document::parse(text).map_err(|e| Failure {
        offset: e.span().map(|s| s.start),
        message: e.message().to_owned(),
    })?;
    let mut starts = HashMap::new();
    let value = table(document.as_table(), "", &mut starts)?;
    Ok(Converted { value, starts })
}

fn table(t: &Table, pointer: &str, starts: &mut HashMap<String, usize>) -> Result<Value, Failure> {
    let mut map = Map::new();
    for (key, item) in t.iter() {
        let child = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
        // A value is located by its own text; a table by its header, or for a dotted key by
        // the key that opens it.
        let start = item_start(item).or_else(|| t.key(key).and_then(|k| k.span()).map(|s| s.start));
        if let Some(start) = start {
            starts.insert(child.clone(), start);
        }
        map.insert(key.to_owned(), convert_item(item, &child, starts)?);
    }
    Ok(Value::Object(map))
}

fn item_start(item: &Item) -> Option<usize> {
    match item {
        Item::Value(v) => v.span().map(|s| s.start),
        Item::Table(t) => t.span().map(|s| s.start),
        Item::ArrayOfTables(a) => a.span().map(|s| s.start),
        Item::None => None,
    }
}

fn convert_item(
    item: &Item,
    pointer: &str,
    starts: &mut HashMap<String, usize>,
) -> Result<Value, Failure> {
    match item {
        Item::None => Ok(Value::Null),
        Item::Value(v) => value(v, pointer, starts),
        Item::Table(t) => table(t, pointer, starts),
        Item::ArrayOfTables(array) => {
            let mut items = Vec::with_capacity(array.len());
            for (i, t) in array.iter().enumerate() {
                let child = format!("{pointer}/{i}");
                if let Some(span) = t.span() {
                    starts.insert(child.clone(), span.start);
                }
                items.push(table(t, &child, starts)?);
            }
            Ok(Value::Array(items))
        }
    }
}

fn value(
    v: &toml_edit::Value,
    pointer: &str,
    starts: &mut HashMap<String, usize>,
) -> Result<Value, Failure> {
    use toml_edit::Value as V;
    Ok(match v {
        V::String(s) => Value::String(s.value().clone()),
        V::Integer(n) => Value::from(*n.value()),
        V::Float(f) => Number::from_f64(*f.value())
            .map(Value::Number)
            .ok_or_else(|| Failure {
                offset: v.span().map(|s| s.start),
                message: "not a finite number".into(),
            })?,
        V::Boolean(b) => Value::Bool(*b.value()),
        V::Datetime(d) => {
            let d = d.value();
            if d.date.is_none() || d.time.is_none() || d.offset.is_none() {
                return Err(Failure {
                    offset: v.span().map(|s| s.start),
                    message: format!(
                        "`{d}` has no time zone; write an offset date-time such as \
                         2026-12-01T00:00:00Z"
                    ),
                });
            }
            Value::String(d.to_string())
        }
        V::Array(array) => {
            let mut items = Vec::with_capacity(array.len());
            for (i, element) in array.iter().enumerate() {
                let child = format!("{pointer}/{i}");
                if let Some(span) = element.span() {
                    starts.insert(child.clone(), span.start);
                }
                items.push(value(element, &child, starts)?);
            }
            Value::Array(items)
        }
        V::InlineTable(t) => {
            let mut map = Map::new();
            for (key, element) in t.iter() {
                let child = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                if let Some(span) = element.span() {
                    starts.insert(child.clone(), span.start);
                }
                map.insert(key.to_owned(), value(element, &child, starts)?);
            }
            Value::Object(map)
        }
    })
}

/// A JSON document, indented, with the keys a reader looks for first (`version`, `name`,
/// `hosts`) before the rest.
pub(crate) fn emit_json(value: &Value) -> String {
    fn write(out: &mut String, value: &Value, depth: usize) {
        let indent = |out: &mut String, depth: usize| {
            for _ in 0..depth {
                out.push_str("  ");
            }
        };
        match value {
            Value::Array(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    write(out, item, depth + 1);
                    out.push_str(if i + 1 < items.len() { ",\n" } else { "\n" });
                }
                indent(out, depth);
                out.push(']');
            }
            Value::Object(map) if !map.is_empty() => {
                out.push_str("{\n");
                let entries = ordered(map);
                for (i, (key, item)) in entries.iter().enumerate() {
                    indent(out, depth + 1);
                    out.push_str(&Value::String((*key).clone()).to_string());
                    out.push_str(": ");
                    write(out, item, depth + 1);
                    out.push_str(if i + 1 < entries.len() { ",\n" } else { "\n" });
                }
                indent(out, depth);
                out.push('}');
            }
            scalar => out.push_str(&scalar.to_string()),
        }
    }
    let mut out = String::new();
    write(&mut out, value, 0);
    out.push('\n');
    out
}

/// A line may be this wide before a value moves to a table of its own, or an array onto
/// several lines.
const WIDTH: usize = 100;

/// A JSON document as TOML text. The document must be an object.
pub(crate) fn emit(document: &Value) -> Result<String, String> {
    let Value::Object(root) = document else {
        return Err("a config is an object at the top level".into());
    };
    let root = normalize_object(root, "", "")?;
    let mut out = String::new();
    write_table(&mut out, &[], &root, false);
    Ok(out)
}

/// `null` in a header map is `false`, `null` elsewhere is no key; an array with a `null` is an
/// error naming the element.
fn normalize(value: &Value, pointer: &str, key: &str) -> Result<Value, String> {
    match value {
        Value::Object(map) => normalize_object(map, pointer, key).map(Value::Object),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| match v {
                Value::Null => Err(format!(
                    "{pointer}/{i}: TOML has no null, and an array element cannot be left out"
                )),
                v => normalize(v, &format!("{pointer}/{i}"), ""),
            })
            .collect::<Result<_, _>>()
            .map(Value::Array),
        v => Ok(v.clone()),
    }
}

fn normalize_object(
    map: &Map<String, Value>,
    pointer: &str,
    key: &str,
) -> Result<Map<String, Value>, String> {
    let header_map = matches!(key, "headers" | "requestHeaders");
    let mut out = Map::new();
    for (k, v) in map {
        let child = format!("{pointer}/{}", k.replace('~', "~0").replace('/', "~1"));
        match v {
            Value::Null if header_map => {
                out.insert(k.clone(), Value::Bool(false));
            }
            Value::Null => {}
            v => {
                out.insert(k.clone(), normalize(v, &child, k)?);
            }
        }
    }
    Ok(out)
}

/// How a key's value is written under its table.
enum Form {
    /// `key = value` on one line, or an array over several.
    Inline,
    /// `[path.key]`.
    Table,
    /// One `[[path.key]]` per element.
    Tables,
}

fn form(key: &str, value: &Value) -> Form {
    let one_line = |inline: &str| key_text(key).len() + 3 + inline.len() <= WIDTH;
    match value {
        Value::Object(_) if one_line(&inline(value)) => Form::Inline,
        Value::Object(_) => Form::Table,
        Value::Array(items)
            if !items.is_empty()
                && items.iter().all(Value::is_object)
                && !one_line(&inline(value)) =>
        {
            Form::Tables
        }
        _ => Form::Inline,
    }
}

/// The keys a reader looks for first come first; the rest follow alphabetically.
fn ordered(map: &Map<String, Value>) -> Vec<(&String, &Value)> {
    const FIRST: [&str; 8] = [
        "version", "name", "hosts", "tls", "listen", "when", "to", "rate",
    ];
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by_key(|(k, _)| FIRST.iter().position(|f| f == k).unwrap_or(FIRST.len()));
    entries
}

fn write_table(out: &mut String, path: &[String], map: &Map<String, Value>, header: bool) {
    if header {
        let _ = writeln!(out, "[{}]", dotted(path));
    }
    for (key, value) in ordered(map) {
        if let Form::Inline = form(key, value) {
            write_pair(out, key, value);
        }
    }
    for (key, value) in ordered(map) {
        let mut child = path.to_vec();
        child.push(key.clone());
        match (form(key, value), value) {
            (Form::Table, Value::Object(t)) => {
                let only_tables = t.iter().all(|(k, v)| !matches!(form(k, v), Form::Inline));
                if !out.is_empty() && !out.ends_with("\n\n") {
                    out.push('\n');
                }
                // A table that holds only tables needs no header of its own.
                write_table(out, &child, t, !only_tables);
            }
            (Form::Tables, Value::Array(items)) => {
                for item in items {
                    let Value::Object(t) = item else {
                        unreachable!("Form::Tables is for arrays of objects")
                    };
                    if !out.is_empty() && !out.ends_with("\n\n") {
                        out.push('\n');
                    }
                    let _ = writeln!(out, "[[{}]]", dotted(&child));
                    write_table(out, &child, t, false);
                }
            }
            _ => {}
        }
    }
}

fn write_pair(out: &mut String, key: &str, value: &Value) {
    let text = inline(value);
    let head = format!("{} = ", key_text(key));
    match value {
        Value::Array(items) if head.len() + text.len() > WIDTH && !items.is_empty() => {
            let _ = writeln!(out, "{head}[");
            for item in items {
                let _ = writeln!(out, "  {},", inline(item));
            }
            out.push_str("]\n");
        }
        _ => {
            let _ = writeln!(out, "{head}{text}");
        }
    }
}

fn dotted(path: &[String]) -> String {
    path.iter()
        .map(|k| key_text(k))
        .collect::<Vec<_>>()
        .join(".")
}

fn key_text(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if bare { key.to_owned() } else { basic(key) }
}

/// A value on one line.
fn inline(value: &Value) -> String {
    match value {
        Value::Null => unreachable!("normalize removes null"),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.to_string(),
            (None, Some(u)) => u.to_string(),
            _ => {
                let f = n.as_f64().unwrap_or(0.0);
                format!("{f:?}")
            }
        },
        Value::String(s) => string(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(inline).collect();
            format!("[{}]", parts.join(", "))
        }
        Value::Object(map) if map.is_empty() => "{}".into(),
        Value::Object(map) => {
            let parts: Vec<String> = ordered(map)
                .into_iter()
                .map(|(k, v)| format!("{} = {}", key_text(k), inline(v)))
                .collect();
            format!("{{ {} }}", parts.join(", "))
        }
    }
}

/// A literal string when it needs no escape, so templates and regexes read as written.
fn string(s: &str) -> String {
    if s.chars()
        .all(|c| c != '\'' && (c == '\t' || !c.is_control()))
    {
        format!("'{s}'")
    } else {
        basic(s)
    }
}

fn basic(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn read(text: &str) -> Value {
        parse(text).ok().expect("valid TOML").value
    }

    #[test]
    fn tables_arrays_and_scalars_convert() {
        let v = read(
            "version = 1\nok = true\nratio = 0.5\n\
             [[sites]]\nname = \"a\"\nhosts = [\"x\", \"y\"]\n\
             [sites.tls]\ncert = \"/c\"\n",
        );
        assert_eq!(
            v,
            json!({"version": 1, "ok": true, "ratio": 0.5,
                   "sites": [{"name": "a", "hosts": ["x", "y"], "tls": {"cert": "/c"}}]})
        );
    }

    #[test]
    fn an_offset_date_time_is_its_rfc_3339_string() {
        let v = read("a = 2026-12-01T00:00:00Z\nb = 1994-11-06 08:49:37+01:00\n");
        assert_eq!(v["a"], "2026-12-01T00:00:00Z");
        assert_eq!(v["b"], "1994-11-06T08:49:37+01:00");
    }

    #[test]
    fn a_local_time_is_an_error_at_its_position() {
        for text in [
            "a = 2026-12-01\n",
            "a = 07:32:00\n",
            "a = 2026-12-01T00:00:00\n",
        ] {
            let e = parse(text).err().unwrap();
            assert_eq!(e.offset, Some(4), "{text}");
            assert!(e.message.contains("no time zone"), "{}", e.message);
        }
    }

    #[test]
    fn values_are_located_by_json_pointer() {
        let text = "version = 1\n[[sites]]\nname = \"a\"\nproxy.to.kubernetes = { port = 1 }\n\
                    tls = { cert = \"/c\" }\n";
        let c = parse(text).ok().unwrap();
        let at = |p: &str| line_column(text, c.starts[p]);
        assert_eq!(at("/version"), (1, 11));
        assert_eq!(at("/sites"), (2, 1));
        assert_eq!(at("/sites/0"), (2, 1));
        assert_eq!(at("/sites/0/name"), (3, 8));
        assert_eq!(at("/sites/0/proxy"), (4, 1));
        assert_eq!(at("/sites/0/proxy/to/kubernetes"), (4, 23));
        assert_eq!(at("/sites/0/tls/cert"), (5, 16));
    }

    #[test]
    fn null_is_false_in_header_maps_and_dropped_elsewhere() {
        let json = json!({"version": 1, "sites": [{
            "name": "a", "tls": null, "headers": {"Server": null, "X-A": "b"},
            "routes": [{"requestHeaders": {"Cookie": null}}, {"proxy": {"to": "http://a:1",
                "headers": {"X-Real-IP": null}}}]}]});
        let text = emit(&json).unwrap();
        assert_eq!(
            read(&text),
            json!({"version": 1, "sites": [{
                "name": "a", "headers": {"Server": false, "X-A": "b"},
                "routes": [{"requestHeaders": {"Cookie": false}}, {"proxy": {"to": "http://a:1",
                    "headers": {"X-Real-IP": false}}}]}]})
        );
        let e = emit(&json!({"a": [1, null]})).unwrap_err();
        assert!(e.starts_with("/a/1: TOML has no null"), "{e}");
    }

    #[test]
    fn emitted_text_reads_back_as_the_same_value() {
        let json = json!({
            "version": 1,
            "listen": {"http": ["0.0.0.0:8080"]},
            "sites": [
                {"name": "app", "hosts": ["*"], "routes": [{"proxy": "http://127.0.0.1:3000"}]},
                {"name": "api", "hosts": ["api.example.com"],
                 "tls": {"cert": "/etc/ssl/a.pem", "key": "/etc/ssl/a.key"},
                 "routes": [
                    {"name": "login", "when": {"path": "/v1/login", "method": "POST"},
                     "limit": {"rate": "5/m", "burst": 5}},
                    {"proxy": {"to": ["http://10.0.1.11:8080", {"url": "http://10.0.1.12:8080", "weight": 2}],
                               "balance": {"hash": "{cookie.cart}"},
                               "health": {"active": {"path": "/healthz", "interval": "5s",
                                                     "expect": [200]}}}},
                    {"respond": {"body": "{{\"a\":\"it's\"}}\nline two\ttab"}}],
                 "errors": [{"status": [429], "routes": [{"respond": {"status": 429}}]}]}
            ],
            "odd key/with~chars": {"a.b": 1, "": 2}
        });
        let text = emit(&json).unwrap();
        assert_eq!(read(&text), json, "{text}");
    }

    #[test]
    fn layout_is_readable() {
        let json = json!({
            "version": 1,
            "sites": [{"name": "app", "hosts": ["*"],
                       "routes": [{"proxy": "http://127.0.0.1:3000"}],
                       "tls": {"cert": "/c", "key": "/k"}}]
        });
        assert_eq!(
            emit(&json).unwrap(),
            "version = 1\n\n[[sites]]\nname = 'app'\nhosts = ['*']\ntls = { cert = '/c', key = '/k' }\n\
             routes = [{ proxy = 'http://127.0.0.1:3000' }]\n"
        );
    }

    #[test]
    fn json_output_is_indented_and_puts_the_names_first() {
        let v = json!({"sites": [{"hosts": ["a"], "name": "x", "routes": []}], "version": 1});
        assert_eq!(
            emit_json(&v),
            "{\n  \"version\": 1,\n  \"sites\": [\n    {\n      \"name\": \"x\",\n      \"hosts\": [\n        \"a\"\n      ],\n      \"routes\": []\n    }\n  ]\n}\n"
        );
        let back: Value = serde_json::from_str(&emit_json(&v)).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn a_top_level_that_is_not_an_object_is_refused() {
        assert!(emit(&json!([1])).is_err());
    }
}
