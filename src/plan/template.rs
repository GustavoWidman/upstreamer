//! Templates: literal bytes and typed placeholders, parsed once at compile time.
//!
//! Placeholders (one spelling each):
//! `{host}` `{remote_host}` (the client's address: the peer's, or the one a trusted proxy
//! forwarded) `{remote_net}` (the client's IPv4 address, or its IPv6 /64 as
//! `2001:db8:1:2::/64`) `{peer_host}` (the address of the connection's peer, always)
//! `{remote_port}` `{scheme}` `{method}` `{path}` `{query}` `{?query}` (empty, or `?` +
//! query) `{uri}` (the request-target as it would go upstream: the client's bytes, or the
//! percent-encoded path and query after a rewrite) `{query.K}` `{cookie.K}` `{header.Name}`
//! (fields joined with ", ") `{vars.k}` `{re.N}` `{err.status_code}` `{err.status_text}`
//! `{err.retry_after}` (seconds until a refused request may retry, empty when it was not
//! refused). Unknown names are compile errors. `{{` and `}}` are literal braces.

use super::VarId;
use crate::exchange::{ASpan, Exchange, Scheme};
use crate::msg::{HeaderName, Known};
use std::io::Write;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Template {
    parts: Box<[Part]>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Part {
    Lit(Box<[u8]>),
    Ph(Placeholder),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Placeholder {
    Host,
    RemoteHost,
    RemoteNet,
    PeerHost,
    /// The default `X-Forwarded-For` of a plan with trusted proxies: the chain a trusted peer
    /// sent, then the peer. Not spelled in templates.
    ForwardedFor,
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
    ErrRetryAfter,
}

/// What `{re.N}` may refer to in the template being parsed.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Captures {
    /// The step's `when` has no `pathRegex` or `regex` at its top level.
    None,
    /// Its one regex has this many groups, group 0 (the whole match) included.
    Groups(u8),
    /// It has more than one, so `{re.N}` would not say which.
    Ambiguous,
    /// A request key (`limit.key`, `balance.hash`): computed from the request alone.
    Unavailable,
}

/// Compile-time context for parsing: interns var names, knows which capture groups the
/// current step's `when` provides, and records what the template reads.
pub(crate) struct Scope<'a> {
    pub vars: &'a mut Vec<Box<str>>,
    pub captures: Captures,
    pub in_error_route: bool,
    /// Set when a parsed template holds a `{re.N}`.
    pub uses_captures: bool,
    /// Every var a parsed template reads, in order.
    pub reads: Vec<VarId>,
}

#[derive(Debug)]
pub(crate) struct TemplateError {
    pub offset: usize,
    pub message: String,
}

/// `{re.N}` reads at most this group, so a step's captures fit a fixed slot array.
pub(crate) const MAX_CAPTURE: u8 = 15;

impl Template {
    pub fn parse(src: &str, scope: &mut Scope<'_>) -> Result<Template, TemplateError> {
        let bytes = src.as_bytes();
        let mut parts: Vec<Part> = Vec::new();
        let mut lit: Vec<u8> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'{' if bytes.get(i + 1) == Some(&b'{') => {
                    lit.push(b'{');
                    i += 2;
                }
                b'}' if bytes.get(i + 1) == Some(&b'}') => {
                    lit.push(b'}');
                    i += 2;
                }
                b'}' => {
                    return Err(TemplateError {
                        offset: i,
                        message: "a lone `}`; write `}}` for a literal brace".into(),
                    });
                }
                b'{' => {
                    let Some(len) = bytes[i + 1..].iter().position(|&b| b == b'}') else {
                        return Err(TemplateError {
                            offset: i,
                            message: "an unclosed `{`; write `{{` for a literal brace".into(),
                        });
                    };
                    let name = &src[i + 1..i + 1 + len];
                    let ph = placeholder(name, scope)
                        .map_err(|message| TemplateError { offset: i, message })?;
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit).into()));
                    }
                    parts.push(Part::Ph(ph));
                    i += len + 2;
                }
                b => {
                    lit.push(b);
                    i += 1;
                }
            }
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit.into()));
        }
        Ok(Template {
            parts: parts.into(),
        })
    }

    /// The single placeholder of a template that is exactly one, such as `{remote_net}`.
    pub fn as_placeholder(&self) -> Option<&Placeholder> {
        match &*self.parts {
            [Part::Ph(ph)] => Some(ph),
            _ => None,
        }
    }

    /// A template of literal bytes only, for values the compiler builds itself.
    pub fn literal(bytes: &[u8]) -> Template {
        Template::from_parts(vec![Part::Lit(bytes.into())])
    }

    pub(crate) fn from_parts(parts: Vec<Part>) -> Template {
        Template {
            parts: parts
                .into_iter()
                .filter(|p| !matches!(p, Part::Lit(l) if l.is_empty()))
                .collect(),
        }
    }

    /// `Some` when the template has no placeholders (folded by the compiler: constant
    /// matchers, constant roots).
    pub fn as_const(&self) -> Option<&[u8]> {
        match &*self.parts {
            [] => Some(b""),
            [Part::Lit(lit)] => Some(lit),
            _ => None,
        }
    }

    /// Expands into the exchange's arena. Placeholders that have no value (unset var, absent
    /// header or cookie) expand to nothing.
    pub fn expand(&self, ex: &mut Exchange) -> ASpan {
        if let Some(lit) = self.as_const() {
            return ex.arena.push(lit);
        }
        let Exchange {
            req,
            conn,
            client,
            trusted_peer,
            vars,
            captures,
            arena,
            error,
            refused,
            ..
        } = ex;
        arena.build(|out| {
            for part in self.parts.iter() {
                let ph = match part {
                    Part::Lit(lit) => {
                        out.extend_from_slice(lit);
                        continue;
                    }
                    Part::Ph(ph) => ph,
                };
                match ph {
                    Placeholder::Host => out.extend_from_slice(req.host()),
                    Placeholder::RemoteHost => {
                        let _ = write!(out, "{client}");
                    }
                    Placeholder::RemoteNet => write_net(out, *client),
                    Placeholder::PeerHost => {
                        let _ = write!(out, "{}", conn.remote.ip());
                    }
                    Placeholder::ForwardedFor => {
                        crate::trust::forwarded_for(req, conn, *trusted_peer, out)
                    }
                    Placeholder::RemotePort => {
                        let _ = write!(out, "{}", conn.remote.port());
                    }
                    Placeholder::Scheme => out.extend_from_slice(match conn.scheme {
                        Scheme::Http => b"http",
                        Scheme::Https => b"https",
                    }),
                    Placeholder::Method => out.extend_from_slice(req.method_bytes()),
                    Placeholder::Path => out.extend_from_slice(req.path().as_bytes()),
                    Placeholder::Query => out.extend_from_slice(req.query().unwrap_or_default()),
                    Placeholder::QuerySuffix => {
                        if let Some(q) = req.query().filter(|q| !q.is_empty()) {
                            out.push(b'?');
                            out.extend_from_slice(q);
                        }
                    }
                    Placeholder::Uri => req.write_upstream_target(out),
                    Placeholder::QueryArg(key) => {
                        if let Some(v) = query_values(req.query(), key).next() {
                            percent_decode_into(v, true, out);
                        }
                    }
                    Placeholder::Cookie(name) => {
                        if let Some(v) = cookie(req.fields.values_known(Known::Cookie), name) {
                            out.extend_from_slice(v);
                        }
                    }
                    Placeholder::Header(name) => {
                        for (i, v) in req.fields.values(name).enumerate() {
                            if i > 0 {
                                out.extend_from_slice(b", ");
                            }
                            out.extend_from_slice(v);
                        }
                    }
                    Placeholder::Var(id) => {
                        if let Some(s) = vars[id.0 as usize] {
                            out.extend_from_within(s.start as usize..s.end as usize);
                        }
                    }
                    Placeholder::Capture(n) => {
                        if let Some(Some(s)) = captures.get(*n as usize) {
                            out.extend_from_within(s.start as usize..s.end as usize);
                        }
                    }
                    Placeholder::ErrStatus => {
                        if let Some(e) = error {
                            let _ = write!(out, "{}", e.status.code());
                        }
                    }
                    Placeholder::ErrText => {
                        if let Some(e) = error {
                            out.extend_from_slice(e.status.text().as_bytes());
                        }
                    }
                    Placeholder::ErrRetryAfter => {
                        if let Some(r) = refused {
                            let _ = write!(out, "{}", r.retry_after);
                        }
                    }
                }
            }
        })
    }
}

fn placeholder(name: &str, scope: &mut Scope<'_>) -> Result<Placeholder, String> {
    let (head, arg) = match name.split_once('.') {
        Some((head, arg)) => (head, Some(arg)),
        None => (name, None),
    };
    let need_arg = |what: &str| -> Result<&str, String> {
        match arg {
            Some(a) if !a.is_empty() => Ok(a),
            _ => Err(format!("`{{{head}.<{what}>}}` needs a {what}")),
        }
    };
    Ok(match (head, arg) {
        ("host", None) => Placeholder::Host,
        ("remote_host", None) => Placeholder::RemoteHost,
        ("remote_net", None) => Placeholder::RemoteNet,
        ("peer_host", None) => Placeholder::PeerHost,
        ("remote_port", None) => Placeholder::RemotePort,
        ("scheme", None) => Placeholder::Scheme,
        ("method", None) => Placeholder::Method,
        ("path", None) => Placeholder::Path,
        ("query", None) => Placeholder::Query,
        ("?query", None) => Placeholder::QuerySuffix,
        ("uri", None) => Placeholder::Uri,
        ("query", Some(_)) => Placeholder::QueryArg(need_arg("key")?.as_bytes().into()),
        ("cookie", Some(_)) => Placeholder::Cookie(need_arg("name")?.as_bytes().into()),
        ("header", Some(_)) => {
            let field = need_arg("field name")?;
            Placeholder::Header(
                HeaderName::new(field)
                    .ok_or_else(|| format!("`{{header.{field}}}`: not a header field name"))?,
            )
        }
        ("vars", Some(_)) => {
            let var = need_arg("name")?;
            let id = intern(scope.vars, var);
            scope.reads.push(id);
            Placeholder::Var(id)
        }
        ("re", Some(_)) => {
            let n = need_arg("group number")?;
            let n: u8 = n
                .parse()
                .ok()
                .filter(|&n| n <= MAX_CAPTURE)
                .ok_or_else(|| format!("`{{re.{n}}}`: the group is a number from 0 to 15"))?;
            match scope.captures {
                Captures::Groups(groups) if n < groups => {}
                Captures::Groups(groups) => {
                    return Err(format!(
                        "`{{re.{n}}}`: the regex in this step's `when` has {} capture group{}",
                        groups - 1,
                        if groups == 2 { "" } else { "s" }
                    ));
                }
                Captures::None => {
                    return Err(format!(
                        "`{{re.{n}}}` needs a `pathRegex` or `regex` in this step's own `when`"
                    ));
                }
                Captures::Ambiguous => {
                    return Err(format!(
                        "`{{re.{n}}}` is ambiguous: this step's `when` has more than one regex"
                    ));
                }
                Captures::Unavailable => {
                    return Err(format!(
                        "`{{re.{n}}}` cannot be read in a key, which is computed from the request alone"
                    ));
                }
            }
            scope.uses_captures = true;
            Placeholder::Capture(n)
        }
        ("err", Some("status_code" | "status_text" | "retry_after")) if !scope.in_error_route => {
            return Err(format!(
                "`{{{name}}}` has a value only inside an error route (`errors`)"
            ));
        }
        ("err", Some("status_code")) => Placeholder::ErrStatus,
        ("err", Some("status_text")) => Placeholder::ErrText,
        ("err", Some("retry_after")) => Placeholder::ErrRetryAfter,
        _ => return Err(format!("unknown placeholder `{{{name}}}`")),
    })
}

/// `{remote_net}`: an IPv4 address as is, an IPv6 address with its low 64 bits zeroed and
/// `/64` appended. An IPv4-mapped IPv6 address is its IPv4 address.
fn write_net(out: &mut Vec<u8>, ip: std::net::IpAddr) {
    match ip.to_canonical() {
        std::net::IpAddr::V4(v4) => {
            let _ = write!(out, "{v4}");
        }
        std::net::IpAddr::V6(v6) => {
            let net = std::net::Ipv6Addr::from_bits(v6.to_bits() & !u128::from(u64::MAX));
            let _ = write!(out, "{net}/64");
        }
    }
}

pub(crate) fn intern(vars: &mut Vec<Box<str>>, name: &str) -> VarId {
    let index = match vars.iter().position(|v| &**v == name) {
        Some(i) => i,
        None => {
            vars.push(name.into());
            vars.len() - 1
        }
    };
    VarId(index as u16)
}

/// Raw values of every `key=value` pair of a query whose decoded key is `key`.
pub(crate) fn query_values<'q>(
    query: Option<&'q [u8]>,
    key: &'q [u8],
) -> impl Iterator<Item = &'q [u8]> + 'q {
    query
        .unwrap_or_default()
        .split(|&b| b == b'&')
        .filter_map(move |pair| {
            let (k, v) = match pair.iter().position(|&b| b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &b""[..]),
            };
            (!pair.is_empty() && decoded_eq(k, key)).then_some(v)
        })
}

/// Whether the form-urlencoded `raw` decodes to `want`, without decoding into a buffer.
pub(crate) fn decoded_eq(raw: &[u8], want: &[u8]) -> bool {
    let mut want = want.iter();
    let mut i = 0;
    while i < raw.len() {
        let (b, n) = decode_at(raw, i, true);
        if want.next() != Some(&b) {
            return false;
        }
        i += n;
    }
    want.next().is_none()
}

/// Percent-decodes `raw` (and `+` as a space for query components) into `out`. A malformed
/// escape is kept as it is.
pub(crate) fn percent_decode_into(raw: &[u8], plus: bool, out: &mut Vec<u8>) {
    let mut i = 0;
    while i < raw.len() {
        let (b, n) = decode_at(raw, i, plus);
        out.push(b);
        i += n;
    }
}

fn decode_at(raw: &[u8], i: usize, plus: bool) -> (u8, usize) {
    fn hex(b: u8) -> Option<u8> {
        (b as char).to_digit(16).map(|d| d as u8)
    }
    match raw[i] {
        b'%' => match (
            raw.get(i + 1).copied().and_then(hex),
            raw.get(i + 2).copied().and_then(hex),
        ) {
            (Some(hi), Some(lo)) => (hi << 4 | lo, 3),
            _ => (b'%', 1),
        },
        b'+' if plus => (b' ', 1),
        b => (b, 1),
    }
}

/// The value of the first cookie named `name` in `Cookie` fields (`a=1; b=2`), without the
/// double quotes a value may be wrapped in.
pub(crate) fn cookie<'a>(fields: impl Iterator<Item = &'a [u8]>, name: &[u8]) -> Option<&'a [u8]> {
    fields
        .flat_map(|field| field.split(|&b| b == b';'))
        .find_map(|pair| {
            let pair = pair.trim_ascii();
            let eq = pair.iter().position(|&b| b == b'=')?;
            (pair[..eq].trim_ascii() == name).then(|| {
                let v = pair[eq + 1..].trim_ascii();
                match v {
                    [b'"', inner @ .., b'"'] => inner,
                    v => v,
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(vars: &mut Vec<Box<str>>, captures: Captures, in_error_route: bool) -> Scope<'_> {
        Scope {
            vars,
            captures,
            in_error_route,
            uses_captures: false,
            reads: Vec::new(),
        }
    }

    fn parse(src: &str) -> Result<Template, String> {
        let mut vars = Vec::new();
        Template::parse(src, &mut scope(&mut vars, Captures::Groups(2), false))
            .map_err(|e| e.message)
    }

    #[test]
    fn literals_and_braces_fold_to_a_constant() {
        assert_eq!(parse("/a/b").unwrap().as_const(), Some(&b"/a/b"[..]));
        assert_eq!(parse("{{x}}").unwrap().as_const(), Some(&b"{x}"[..]));
        assert_eq!(parse("").unwrap().as_const(), Some(&b""[..]));
        assert_eq!(parse("/{path}").unwrap().as_const(), None);
    }

    #[test]
    fn placeholder_errors() {
        assert_eq!(parse("{nope}").unwrap_err(), "unknown placeholder `{nope}`");
        assert_eq!(
            parse("{re.2}").unwrap_err(),
            "`{re.2}`: the regex in this step's `when` has 1 capture group"
        );
        assert_eq!(
            parse("{err.status_code}").unwrap_err(),
            "`{err.status_code}` has a value only inside an error route (`errors`)"
        );
        assert_eq!(
            parse("{header.a b}").unwrap_err(),
            "`{header.a b}`: not a header field name"
        );
        assert_eq!(
            parse("/{path").unwrap_err(),
            "an unclosed `{`; write `{{` for a literal brace"
        );
        assert_eq!(
            parse("a}b").unwrap_err(),
            "a lone `}`; write `}}` for a literal brace"
        );
        assert!(parse("{re.1}").is_ok());
        let mut vars = Vec::new();
        let e = Template::parse("{re.0}", &mut scope(&mut vars, Captures::None, false))
            .unwrap_err()
            .message;
        assert_eq!(
            e,
            "`{re.0}` needs a `pathRegex` or `regex` in this step's own `when`"
        );
    }

    #[test]
    fn vars_are_interned_once() {
        let mut vars = Vec::new();
        let mut s = scope(&mut vars, Captures::None, false);
        Template::parse("{vars.a}{vars.b}{vars.a}", &mut s).unwrap();
        assert_eq!(s.reads, [VarId(0), VarId(1), VarId(0)]);
        assert_eq!(vars, [Box::from("a"), Box::from("b")]);
    }

    #[test]
    fn query_and_cookie_lookup() {
        let q = Some(&b"a=1&lang=p%74&x&lang=en&l%61ng=de+x"[..]);
        let values: Vec<&[u8]> = query_values(q, b"lang").collect();
        assert_eq!(values, [&b"p%74"[..], b"en", b"de+x"]);
        let mut out = Vec::new();
        percent_decode_into(b"de+x%2F%zz", true, &mut out);
        assert_eq!(out, b"de x/%zz");
        assert!(decoded_eq(b"p%74", b"pt"));
        assert!(!decoded_eq(b"p%74", b"p"));

        let fields = [&b"a=1; site_lang=\"pt\""[..], b"b=2"];
        assert_eq!(cookie(fields.into_iter(), b"site_lang"), Some(&b"pt"[..]));
        assert_eq!(cookie(fields.into_iter(), b"b"), Some(&b"2"[..]));
        assert_eq!(cookie(fields.into_iter(), b"c"), None);
    }

    fn expand(src: &str, client: &str, refused: Option<u32>) -> String {
        use crate::exchange::{ConnInfo, Proto, Refused, RefusedBy, Scheme};
        use crate::plan::{ListenerKey, ListenerKind};
        let mut vars = Vec::new();
        let t = Template::parse(src, &mut scope(&mut vars, Captures::None, true)).unwrap();
        let conn = ConnInfo {
            remote: "198.51.100.7:40000".parse().unwrap(),
            local_port: 443,
            scheme: Scheme::Https,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:443".parse().unwrap(),
                kind: ListenerKind::Https,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        ex.client = client.parse().unwrap();
        ex.refused = refused.map(|retry_after| Refused {
            by: RefusedBy::Limit,
            retry_after,
        });
        let span = t.expand(&mut ex);
        String::from_utf8(ex.arena.get(span).to_vec()).unwrap()
    }

    #[test]
    fn client_peer_and_network_placeholders() {
        assert_eq!(
            expand("{remote_host} {peer_host}", "203.0.113.9", None),
            "203.0.113.9 198.51.100.7",
            "the client is what a trusted proxy forwarded; the peer is the connection's"
        );
        assert_eq!(expand("{remote_net}", "203.0.113.9", None), "203.0.113.9");
        assert_eq!(
            expand("{remote_net}", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", None),
            "2001:db8:1:2::/64"
        );
        assert_eq!(
            expand("{remote_net}", "::ffff:192.0.2.1", None),
            "192.0.2.1"
        );
    }

    #[test]
    fn retry_after_is_empty_unless_the_request_was_refused() {
        assert_eq!(expand("[{err.retry_after}]", "192.0.2.1", Some(7)), "[7]");
        assert_eq!(expand("[{err.retry_after}]", "192.0.2.1", None), "[]");
        assert_eq!(
            parse("{err.retry_after}").unwrap_err(),
            "`{err.retry_after}` has a value only inside an error route (`errors`)"
        );
    }
}
