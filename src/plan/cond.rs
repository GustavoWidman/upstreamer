//! Compiled matchers. A boolean tree over a handful of typed tests; the evaluator is in
//! `route.rs` because it needs the request, the regex caches and the file catalog.

use super::{FileProbe, RegexId, Template};
use crate::msg::HeaderName;

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
    /// Globs over the field values joined with ", ".
    Header {
        name: HeaderName,
        globs: Box<[Glob]>,
    },
    HeaderRegex {
        name: HeaderName,
        regex: RegexId,
    },
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

/// Path patterns split by shape at compile time so the common ones are a slice compare.
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

/// A `*`-only glob, split at the stars.
#[derive(Debug)]
pub(crate) struct Glob {
    pub pieces: Box<[Box<[u8]>]>,
    pub anchored_start: bool,
    pub anchored_end: bool,
}

impl Glob {
    pub fn matches(&self, s: &[u8]) -> bool {
        todo!()
    }
}

/// Bit per [`crate::msg::Method`]; `Other` methods are matched by name in `others`.
#[derive(Debug, Default)]
pub(crate) struct MethodSet {
    pub bits: u16,
    pub others: Box<[Box<[u8]>]>,
}
