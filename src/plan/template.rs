//! Templates: literal bytes and typed placeholders, parsed once at compile time.
//!
//! Placeholders (one spelling each):
//! `{host}` `{remote_host}` `{remote_port}` `{scheme}` `{method}` `{path}` `{query}`
//! `{?query}` (empty, or `?` + query) `{uri}` (path + `{?query}`) `{query.K}` `{cookie.K}`
//! `{header.Name}` (fields joined with ", ") `{vars.k}` `{re.N}` `{err.status_code}`
//! `{err.status_text}`. Unknown names are compile errors. `{{` and `}}` are literal braces.

use super::VarId;
use crate::exchange::{ASpan, Exchange};
use crate::msg::HeaderName;

#[derive(Debug)]
pub(crate) struct Template {
    parts: Box<[Part]>,
}

#[derive(Debug)]
pub(crate) enum Part {
    Lit(Box<[u8]>),
    Ph(Placeholder),
}

#[derive(Debug)]
pub(crate) enum Placeholder {
    Host,
    RemoteHost,
    RemotePort,
    Scheme,
    Method,
    Path,
    Query,
    QuerySuffix,
    Uri,
    QueryArg(Box<[u8]>),
    Cookie(Box<[u8]>),
    Header(HeaderName),
    Var(VarId),
    /// Group N of the regex in the same step's `when`.
    Capture(u8),
    ErrStatus,
    ErrText,
}

/// Compile-time context for parsing: interns var names, knows which capture groups the
/// current step's `when` provides.
pub(crate) struct Scope<'a> {
    pub vars: &'a mut Vec<Box<str>>,
    pub capture_groups: u8,
    pub in_error_route: bool,
}

#[derive(Debug)]
pub(crate) struct TemplateError {
    pub offset: usize,
    pub message: &'static str,
}

impl Template {
    pub fn parse(src: &str, scope: &mut Scope<'_>) -> Result<Template, TemplateError> {
        todo!()
    }
    /// `Some` when the template has no placeholders (folded by the compiler: constant
    /// matchers, constant roots).
    pub fn as_const(&self) -> Option<&[u8]> {
        todo!()
    }
    /// Expands into the exchange's arena. Placeholders that have no value (unset var, absent
    /// header or cookie) expand to nothing.
    pub fn expand(&self, ex: &mut Exchange) -> ASpan {
        todo!()
    }
}
