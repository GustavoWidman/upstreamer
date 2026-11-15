//! Compiled matchers. A boolean tree over a handful of typed tests; the evaluator is in
//! `route.rs` because it needs the request, the regex caches and the file catalog.

use super::{FileProbe, RegexId, Template};
use crate::msg::{HeaderName, Method};

#[derive(Debug)]
pub(crate) enum Cond {
    All(Box<[Cond]>),
    Any(Box<[Cond]>),
    /// None of them holds.
    None(Box<[Cond]>),
    Test(Test),
}

#[derive(Debug)]
pub(crate) enum Test {
    Path(PathPatterns),
    /// Captures (if the step uses `{re.N}`) are copied into the exchange's arena on a match.
    PathRegex {
        regex: RegexId,
        captures: bool,
    },
    Method(MethodSet),
    /// Globs over the field values joined with ", ". An absent field never matches.
    Header {
        name: HeaderName,
        globs: Box<[Glob]>,
    },
    /// A regex over the field values joined with ", ". An absent field never matches.
    HeaderRegex {
        name: HeaderName,
        regex: RegexId,
    },
    /// Some value of `key` (both percent-decoded) is one of `values`.
    Query {
        key: Box<[u8]>,
        values: Box<[Box<[u8]>]>,
    },
    ValueIn {
        value: Template,
        set: Box<[Box<[u8]>]>,
    },
    ValueRegex {
        value: Template,
        regex: RegexId,
        captures: bool,
    },
    File(FileProbe),
    After(i64),
}

impl Test {
    /// Relative cost, so the compiler can order an `All` cheapest first: byte compares, then
    /// header scans and template expansions, then regexes, then file system probes.
    pub(crate) fn cost(&self) -> u8 {
        match self {
            Test::Path(_) | Test::Method(_) | Test::After(_) => 0,
            Test::Query { .. } | Test::ValueIn { .. } | Test::Header { .. } => 1,
            Test::PathRegex { .. } | Test::HeaderRegex { .. } | Test::ValueRegex { .. } => 2,
            Test::File(_) => 3,
        }
    }
}

impl Cond {
    pub(crate) fn cost(&self) -> u8 {
        match self {
            Cond::Test(t) => t.cost(),
            Cond::All(cs) | Cond::Any(cs) | Cond::None(cs) => {
                cs.iter().map(Cond::cost).max().unwrap_or(0)
            }
        }
    }
}

/// Path patterns split by shape at compile time so the common ones are a slice compare.
/// Paths match ASCII case-insensitively, as Caddy's `path` matcher does: `/API/sync` takes
/// the `/api/*` route, and `/_MD/x` is refused like `/_md/x`.
#[derive(Debug, Default)]
pub(crate) struct PathPatterns {
    pub exact: Box<[Box<[u8]>]>,
    /// `/api/*` -> `/api/`
    pub prefix: Box<[Box<[u8]>]>,
    /// `*.etag` -> `.etag`
    pub suffix: Box<[Box<[u8]>]>,
    /// Anything with an inner `*`.
    pub glob: Box<[Glob]>,
}

impl PathPatterns {
    pub fn matches(&self, path: &[u8]) -> bool {
        self.exact.iter().any(|p| p.eq_ignore_ascii_case(path))
            || self
                .prefix
                .iter()
                .any(|p| path.len() >= p.len() && path[..p.len()].eq_ignore_ascii_case(p))
            || self.suffix.iter().any(|p| {
                path.len() >= p.len() && path[path.len() - p.len()..].eq_ignore_ascii_case(p)
            })
            || self.glob.iter().any(|g| g.matches_with(path, true))
    }
}

/// A `*`-only glob, split at the stars.
#[derive(Debug)]
pub(crate) struct Glob {
    pub pieces: Box<[Box<[u8]>]>,
    pub anchored_start: bool,
    pub anchored_end: bool,
}

impl Glob {
    /// `*` matches any run of bytes, `/` included; nothing else is special.
    pub fn new(pattern: &[u8]) -> Glob {
        let pieces: Vec<Box<[u8]>> = pattern
            .split(|&b| b == b'*')
            .filter(|p| !p.is_empty())
            .map(Box::from)
            .collect();
        Glob {
            pieces: pieces.into(),
            anchored_start: !pattern.starts_with(b"*"),
            anchored_end: !pattern.ends_with(b"*"),
        }
    }

    pub fn matches(&self, s: &[u8]) -> bool {
        self.matches_with(s, false)
    }

    /// `fold`: compare ASCII letters case-insensitively.
    pub fn matches_with(&self, s: &[u8], fold: bool) -> bool {
        let starts = |s: &[u8], p: &[u8]| s.len() >= p.len() && eq(&s[..p.len()], p, fold);
        let mut pieces = &*self.pieces;
        let mut rest = s;
        if self.anchored_start {
            match pieces.split_first() {
                Some((first, tail)) => {
                    if !starts(rest, first) {
                        return false;
                    }
                    rest = &rest[first.len()..];
                    pieces = tail;
                }
                // A pattern with no star and no bytes matches only the empty string.
                None => return rest.is_empty(),
            }
        }
        let last = if self.anchored_end {
            match pieces.split_last() {
                Some((last, init)) => {
                    pieces = init;
                    Some(last)
                }
                None if self.anchored_start => return rest.is_empty(),
                None => None,
            }
        } else {
            None
        };
        for piece in pieces {
            let found = if fold {
                rest.windows(piece.len())
                    .position(|w| w.eq_ignore_ascii_case(piece))
            } else {
                memchr::memmem::find(rest, piece)
            };
            match found {
                Some(i) => rest = &rest[i + piece.len()..],
                None => return false,
            }
        }
        match last {
            Some(last) => {
                rest.len() >= last.len() && eq(&rest[rest.len() - last.len()..], last, fold)
            }
            None => true,
        }
    }
}

fn eq(a: &[u8], b: &[u8], fold: bool) -> bool {
    if fold {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Bit per [`crate::msg::Method`]; `Other` methods are matched by name in `others`.
#[derive(Debug, Default)]
pub(crate) struct MethodSet {
    pub bits: u16,
    pub others: Box<[Box<[u8]>]>,
}

impl MethodSet {
    pub fn insert(&mut self, token: &[u8]) {
        match Method::from_bytes(token) {
            Method::Other => {
                let mut others = std::mem::take(&mut self.others).into_vec();
                others.push(token.into());
                self.others = others.into();
            }
            known => self.bits |= 1 << known as u16,
        }
    }

    pub fn contains(&self, method: Method, token: &[u8]) -> bool {
        match method {
            Method::Other => self.others.iter().any(|o| **o == *token),
            known => self.bits & (1 << known as u16) != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        let cases: &[(&str, &str, bool)] = &[
            ("curl/*", "curl/8.5.0", true),
            ("curl/*", "Wget/1.0", false),
            ("curl/*", "curl/", true),
            ("*.etag", "/a/b.etag", true),
            ("*.etag", "/a/b.etag.html", false),
            ("/a/*/c", "/a/b/c", true),
            ("/a/*/c", "/a/b/x/c", true),
            ("/a/*/c", "/a/c", false),
            ("*bot*", "Mozilla examplebot/2", true),
            ("*bot*", "Mozilla", false),
            ("a*a", "a", false),
            ("a*a", "aa", true),
            ("*", "", true),
            ("*", "anything", true),
            ("exact", "exact", true),
            ("exact", "exactly", false),
            ("", "", true),
            ("", "x", false),
        ];
        for &(pattern, s, want) in cases {
            assert_eq!(
                Glob::new(pattern.as_bytes()).matches(s.as_bytes()),
                want,
                "{pattern:?} on {s:?}"
            );
        }
    }

    #[test]
    fn methods() {
        let mut set = MethodSet::default();
        set.insert(b"GET");
        set.insert(b"PURGE");
        assert!(set.contains(Method::Get, b"GET"));
        assert!(!set.contains(Method::Head, b"HEAD"));
        assert!(set.contains(Method::Other, b"PURGE"));
        assert!(!set.contains(Method::Other, b"get"));
    }
}
