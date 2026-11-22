//! Protocol-neutral message heads. h1 parses into them, h2/h3 convert into them, the router and
//! the proxy read and edit them, and the h1 encoder serialises them.
//!
//! A head owns one byte buffer holding everything it refers to (start line pieces, the
//! decoded path, header names and values) plus a small table of spans into it. The buffer is a
//! `Vec<u8>` recycled with its [`crate::exchange::Exchange`], so filling a head allocates
//! nothing once a connection has served its first request, and no refcount is touched.
//!
//! Header lookups the proxy does itself (Host, Connection, Content-Length, ...) go through a
//! [`Known`] tag assigned once when a field is added, never through string comparison.
//!
//! Building a request head, for every producer (h1 codec, h2/h3 adapters, tests):
//! [`RequestHead::clear`], [`RequestHead::set_line`], [`RequestHead::push_field`] per field,
//! then [`RequestHead::set_host`].

use smallvec::SmallVec;

/// Byte range into the owning head's buffer. Heads are capped well below 4 GiB, so `u32`
/// suffices.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    fn new(start: usize, end: usize) -> Span {
        Span {
            start: start as u32,
            end: end as u32,
        }
    }
    pub fn len(self) -> usize {
        (self.end - self.start) as usize
    }
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
    pub fn get(self, buf: &[u8]) -> &[u8] {
        &buf[self.start as usize..self.end as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Connect,
    Trace,
    /// Any other token; its bytes are in the head buffer, see [`RequestHead::method_bytes`].
    Other,
}

impl Method {
    /// Methods are case-sensitive (RFC 9110 §9.1): `get` is an `Other` method.
    pub fn from_bytes(token: &[u8]) -> Method {
        match token {
            b"GET" => Method::Get,
            b"HEAD" => Method::Head,
            b"POST" => Method::Post,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"OPTIONS" => Method::Options,
            b"PATCH" => Method::Patch,
            b"CONNECT" => Method::Connect,
            b"TRACE" => Method::Trace,
            _ => Method::Other,
        }
    }

    /// Safe to replay on a fresh upstream connection when a pooled one failed before any byte
    /// of the response arrived.
    pub fn idempotent(self) -> bool {
        matches!(
            self,
            Method::Get
                | Method::Head
                | Method::Options
                | Method::Put
                | Method::Delete
                | Method::Trace
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Version {
    Http10,
    Http11,
    H2,
    H3,
}

/// A status code known to be in 100..=999 (validated where it is created).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct Status(u16);

impl Status {
    pub const CONTINUE: Status = Status(100);
    pub const SWITCHING_PROTOCOLS: Status = Status(101);
    pub const OK: Status = Status(200);
    pub const NO_CONTENT: Status = Status(204);
    pub const PARTIAL_CONTENT: Status = Status(206);
    pub const MOVED_PERMANENTLY: Status = Status(301);
    pub const FOUND: Status = Status(302);
    pub const NOT_MODIFIED: Status = Status(304);
    pub const PERMANENT_REDIRECT: Status = Status(308);
    pub const BAD_REQUEST: Status = Status(400);
    pub const NOT_FOUND: Status = Status(404);
    pub const RANGE_NOT_SATISFIABLE: Status = Status(416);
    pub const MISDIRECTED: Status = Status(421);
    pub const TOO_MANY_REQUESTS: Status = Status(429);
    pub const HEADER_FIELDS_TOO_LARGE: Status = Status(431);
    pub const INTERNAL_SERVER_ERROR: Status = Status(500);
    pub const BAD_GATEWAY: Status = Status(502);
    pub const SERVICE_UNAVAILABLE: Status = Status(503);
    pub const GATEWAY_TIMEOUT: Status = Status(504);
    pub const HTTP_VERSION_NOT_SUPPORTED: Status = Status(505);

    pub fn new(code: u16) -> Option<Status> {
        (100..=999).contains(&code).then_some(Status(code))
    }
    pub fn code(self) -> u16 {
        self.0
    }
    /// Reason phrase for `{err.status_text}` and the h1 status line; `""` for unknown codes.
    pub fn text(self) -> &'static str {
        match self.0 {
            100 => "Continue",
            101 => "Switching Protocols",
            103 => "Early Hints",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Content Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            421 => "Misdirected Request",
            422 => "Unprocessable Content",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            _ => "",
        }
    }
    pub fn is_error(self) -> bool {
        self.0 >= 400
    }
    /// 1xx, 204 and 304 never carry a body (RFC 9110 §6.4.1).
    pub fn has_body(self) -> bool {
        !(self.0 < 200 || self.0 == 204 || self.0 == 304)
    }
}

/// Headers the proxy interprets. Assigned when a field is added, from its lowercase name;
/// everything else is `Other`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Known {
    Host,
    Connection,
    ContentLength,
    TransferEncoding,
    Upgrade,
    Te,
    Trailer,
    KeepAlive,
    ProxyConnection,
    Expect,
    AcceptEncoding,
    IfNoneMatch,
    IfModifiedSince,
    IfRange,
    Range,
    Cookie,
    ContentType,
    ContentEncoding,
    CacheControl,
    Vary,
    ETag,
    LastModified,
    Date,
    Server,
    AltSvc,
    XForwardedFor,
    XForwardedProto,
    XForwardedHost,
    Other,
}

impl Known {
    /// The tag of a lowercase field name.
    pub fn from_lowercase(name: &[u8]) -> Known {
        match name {
            b"host" => Known::Host,
            b"connection" => Known::Connection,
            b"content-length" => Known::ContentLength,
            b"transfer-encoding" => Known::TransferEncoding,
            b"upgrade" => Known::Upgrade,
            b"te" => Known::Te,
            b"trailer" => Known::Trailer,
            b"keep-alive" => Known::KeepAlive,
            b"proxy-connection" => Known::ProxyConnection,
            b"expect" => Known::Expect,
            b"accept-encoding" => Known::AcceptEncoding,
            b"if-none-match" => Known::IfNoneMatch,
            b"if-modified-since" => Known::IfModifiedSince,
            b"if-range" => Known::IfRange,
            b"range" => Known::Range,
            b"cookie" => Known::Cookie,
            b"content-type" => Known::ContentType,
            b"content-encoding" => Known::ContentEncoding,
            b"cache-control" => Known::CacheControl,
            b"vary" => Known::Vary,
            b"etag" => Known::ETag,
            b"last-modified" => Known::LastModified,
            b"date" => Known::Date,
            b"server" => Known::Server,
            b"alt-svc" => Known::AltSvc,
            b"x-forwarded-for" => Known::XForwardedFor,
            b"x-forwarded-proto" => Known::XForwardedProto,
            b"x-forwarded-host" => Known::XForwardedHost,
            _ => Known::Other,
        }
    }

    /// The tag of a name in any case. Only for short tokens such as `Connection` options; field
    /// names are lowercased once when the field is added and tagged with [`Known::from_lowercase`].
    fn from_lowercase_ci(name: &[u8]) -> Known {
        let mut lower = [0u8; 24];
        match lower.get_mut(..name.len()) {
            Some(l) => {
                l.copy_from_slice(name);
                l.make_ascii_lowercase();
                Known::from_lowercase(l)
            }
            None => Known::Other,
        }
    }

    /// The lowercase name; empty for `Other`.
    pub fn name(self) -> &'static [u8] {
        match self {
            Known::Host => b"host",
            Known::Connection => b"connection",
            Known::ContentLength => b"content-length",
            Known::TransferEncoding => b"transfer-encoding",
            Known::Upgrade => b"upgrade",
            Known::Te => b"te",
            Known::Trailer => b"trailer",
            Known::KeepAlive => b"keep-alive",
            Known::ProxyConnection => b"proxy-connection",
            Known::Expect => b"expect",
            Known::AcceptEncoding => b"accept-encoding",
            Known::IfNoneMatch => b"if-none-match",
            Known::IfModifiedSince => b"if-modified-since",
            Known::IfRange => b"if-range",
            Known::Range => b"range",
            Known::Cookie => b"cookie",
            Known::ContentType => b"content-type",
            Known::ContentEncoding => b"content-encoding",
            Known::CacheControl => b"cache-control",
            Known::Vary => b"vary",
            Known::ETag => b"etag",
            Known::LastModified => b"last-modified",
            Known::Date => b"date",
            Known::Server => b"server",
            Known::AltSvc => b"alt-svc",
            Known::XForwardedFor => b"x-forwarded-for",
            Known::XForwardedProto => b"x-forwarded-proto",
            Known::XForwardedHost => b"x-forwarded-host",
            Known::Other => b"",
        }
    }

    /// Hop-by-hop: never forwarded, whatever the config says.
    pub fn hop_by_hop(self) -> bool {
        matches!(
            self,
            Known::Connection
                | Known::TransferEncoding
                | Known::Upgrade
                | Known::Te
                | Known::Trailer
                | Known::KeepAlive
                | Known::ProxyConnection
        )
    }

    /// Framing headers the config may not set (the codec owns them).
    pub fn framing(self) -> bool {
        matches!(
            self,
            Known::ContentLength
                | Known::TransferEncoding
                | Known::Connection
                | Known::ContentEncoding
        )
    }
}

/// RFC 9110 `tchar`.
pub(crate) fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A validated, lowercased header name with its tag. Built by the compiler from config names;
/// `name` is ASCII lowercase tchar only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeaderName {
    pub name: Box<[u8]>,
    pub tag: Known,
}

impl HeaderName {
    /// `None` when `name` is empty or holds a byte that is not a token character.
    pub fn new(name: &str) -> Option<HeaderName> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || !bytes.iter().all(|&b| is_tchar(b)) {
            return None;
        }
        let lower: Box<[u8]> = bytes.to_ascii_lowercase().into();
        let tag = Known::from_lowercase(&lower);
        Some(HeaderName { name: lower, tag })
    }

    fn matches(&self, field: &Field, buf: &[u8]) -> bool {
        match self.tag {
            Known::Other => field.tag == Known::Other && field.name.get(buf) == &*self.name,
            tag => field.tag == tag,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Field {
    pub name: Span,
    pub value: Span,
    pub tag: Known,
    /// Cleared instead of shifting the table when a field is removed.
    pub live: bool,
}

/// The header block of one head: an append-only byte buffer and a field table into it.
/// Edits append (set) or clear `live` (remove); nothing is moved, so spans stay valid.
/// Names are stored lowercase; values with surrounding spaces and tabs trimmed.
#[derive(Debug, Default)]
pub(crate) struct Fields {
    pub buf: Vec<u8>,
    pub table: SmallVec<[Field; 24]>,
}

fn trim_ows(v: &[u8]) -> &[u8] {
    let start = v
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(v.len());
    let end = v
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map_or(start, |i| i + 1);
    &v[start..end]
}

impl Fields {
    pub fn clear(&mut self) {
        self.buf.clear();
        self.table.clear();
    }

    fn copy(&mut self, bytes: &[u8]) -> Span {
        let start = self.buf.len();
        self.buf.extend_from_slice(bytes);
        Span::new(start, self.buf.len())
    }

    /// Appends a field with a wire name of any case (lowercased here) and tags it.
    pub fn push(&mut self, name: &[u8], value: &[u8]) {
        let start = self.buf.len();
        self.buf.extend(name.iter().map(u8::to_ascii_lowercase));
        let name = Span::new(start, self.buf.len());
        let tag = Known::from_lowercase(name.get(&self.buf));
        let value = self.copy(trim_ows(value));
        self.table.push(Field {
            name,
            value,
            tag,
            live: true,
        });
    }

    /// First live field with this tag.
    pub fn get(&self, tag: Known) -> Option<&[u8]> {
        debug_assert!(tag != Known::Other, "look up other fields by name");
        self.table
            .iter()
            .find(|f| f.live && f.tag == tag)
            .map(|f| f.value.get(&self.buf))
    }

    /// Values of every live field with this tag.
    pub fn values_known(&self, tag: Known) -> impl Iterator<Item = &[u8]> + '_ {
        debug_assert!(tag != Known::Other, "look up other fields by name");
        self.table
            .iter()
            .filter(move |f| f.live && f.tag == tag)
            .map(|f| f.value.get(&self.buf))
    }

    /// Values of every live field with this name, for `{header.X}` and header matchers.
    pub fn values<'a>(&'a self, name: &'a HeaderName) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.table
            .iter()
            .filter(move |f| f.live && name.matches(f, &self.buf))
            .map(|f| f.value.get(&self.buf))
    }

    pub fn remove(&mut self, name: &HeaderName) {
        let buf = &self.buf;
        for f in self
            .table
            .iter_mut()
            .filter(|f| f.live && name.matches(f, buf))
        {
            f.live = false;
        }
    }

    pub fn remove_known(&mut self, tag: Known) {
        debug_assert!(tag != Known::Other, "remove other fields by name");
        for f in self.table.iter_mut().filter(|f| f.live && f.tag == tag) {
            f.live = false;
        }
    }

    /// Replaces every field of this name with one field holding `value`.
    pub fn set(&mut self, name: &HeaderName, value: &[u8]) {
        self.remove(name);
        self.append(name, value);
    }

    pub fn set_known(&mut self, tag: Known, value: &[u8]) {
        self.remove_known(tag);
        self.append_known(tag, value);
    }

    pub fn append(&mut self, name: &HeaderName, value: &[u8]) {
        let name_span = self.copy(&name.name);
        let value = self.copy(value);
        self.table.push(Field {
            name: name_span,
            value,
            tag: name.tag,
            live: true,
        });
    }

    pub fn append_known(&mut self, tag: Known, value: &[u8]) {
        debug_assert!(tag != Known::Other, "append other fields by name");
        let name = self.copy(tag.name());
        let value = self.copy(value);
        self.table.push(Field {
            name,
            value,
            tag,
            live: true,
        });
    }

    /// Every live field in order: (lowercase name, value, tag).
    pub fn live(&self) -> impl Iterator<Item = (&[u8], &[u8], Known)> + '_ {
        self.table
            .iter()
            .filter(|f| f.live)
            .map(|f| (f.name.get(&self.buf), f.value.get(&self.buf), f.tag))
    }

    /// Whether a comma-separated field with this tag lists `token` (ASCII case-insensitive),
    /// as in `Connection: keep-alive, Upgrade`.
    pub fn has_token(&self, tag: Known, token: &[u8]) -> bool {
        self.values_known(tag)
            .flat_map(|v| v.split(|&b| b == b','))
            .any(|t| trim_ows(t).eq_ignore_ascii_case(token))
    }

    /// Removes the fields a received `Connection` names (RFC 9110 §7.6.1), so they never
    /// cross this hop. Hop-by-hop fields stay for the codec to read (the writers never emit
    /// them), and so do Host and the framing fields, which the codec has already interpreted.
    /// `close` is the connection option of RFC 9112 §9.6, never a field name: the writers
    /// send it themselves.
    pub fn drop_connection_named(&mut self) {
        let Fields { buf, table } = self;
        for c in 0..table.len() {
            if !(table[c].live && table[c].tag == Known::Connection) {
                continue;
            }
            for token in table[c].value.get(buf).split(|&b| b == b',').map(trim_ows) {
                if token.is_empty()
                    || token.eq_ignore_ascii_case(b"close")
                    || Known::from_lowercase_ci(token).hop_by_hop()
                {
                    continue;
                }
                for f in table.iter_mut().filter(|f| {
                    f.live
                        && !f.tag.hop_by_hop()
                        && !matches!(
                            f.tag,
                            Known::Host | Known::ContentLength | Known::TransferEncoding
                        )
                        && f.name.get(buf).eq_ignore_ascii_case(token)
                }) {
                    f.live = false;
                }
            }
        }
    }

    /// Appends one field whose value is `values` joined by `sep`, as h2/h3 cookie crumbs are
    /// joined for HTTP/1.1 (RFC 9113 §8.2.3). Values are copied as given.
    fn push_joined<'v>(&mut self, name: &[u8], values: impl Iterator<Item = &'v [u8]>, sep: &[u8]) {
        let name = self.copy(name);
        let tag = Known::from_lowercase(name.get(&self.buf));
        let start = self.buf.len();
        for (i, v) in values.enumerate() {
            if i > 0 {
                self.buf.extend_from_slice(sep);
            }
            self.buf.extend_from_slice(v);
        }
        self.table.push(Field {
            name,
            value: Span::new(start, self.buf.len()),
            tag,
            live: true,
        });
    }
}

/// A path that starts with `/`, is percent-decoded, and has no empty, `.` or `..` segments,
/// except that a trailing `/` is kept (`/blog/` and `/blog` are different paths). Only
/// [`clean_path`] and the head's edits make one, so a file root joined with it cannot escape
/// the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CleanPath<'a>(&'a [u8]);

impl<'a> CleanPath<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decodes `%XX`, then resolves dot segments and merges slashes, appending the result to
/// `out`. Decoding comes first, so `%2e%2e` and `%2f` cannot smuggle a segment past the
/// resolution. `None` for a path that does not start with `/`, holds a malformed escape, or
/// climbs above the root with `..`. A decoded `%00` or other control byte is kept and left to
/// matchers. Allocation-free once `out` has capacity (paths with more than 32 segments use a
/// heap stack).
pub(crate) fn clean_path(raw_path: &[u8], out: &mut Vec<u8>) -> Option<Span> {
    let start = out.len();
    let mut i = 0;
    while i < raw_path.len() {
        let b = raw_path[i];
        if b == b'%' {
            let hi = raw_path.get(i + 1).copied().and_then(hex);
            let lo = raw_path.get(i + 2).copied().and_then(hex);
            match (hi, lo) {
                (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
                _ => {
                    out.truncate(start);
                    return None;
                }
            }
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    let span = normalize(out, start);
    if span.is_none() {
        out.truncate(start);
    }
    span
}

/// Resolves dot segments and empty segments of the decoded path in `out[start..]`, in place.
fn normalize(out: &mut Vec<u8>, start: usize) -> Option<Span> {
    let end = out.len();
    if out.get(start) != Some(&b'/') {
        return None;
    }
    let mut stack: SmallVec<[(u32, u32); 32]> = SmallVec::new();
    let mut trailing = false;
    let mut pos = start;
    while pos < end {
        let seg_start = pos + 1;
        let seg_end = out[seg_start..end]
            .iter()
            .position(|&b| b == b'/')
            .map_or(end, |n| seg_start + n);
        let seg = &out[seg_start..seg_end];
        trailing = seg_end == end && (seg.is_empty() || seg == b"." || seg == b"..");
        match seg {
            b"" | b"." => {}
            b".." => {
                stack.pop()?;
            }
            _ => stack.push((seg_start as u32, seg_end as u32)),
        }
        pos = seg_end;
    }
    for &(s, e) in &stack {
        out.push(b'/');
        out.extend_from_within(s as usize..e as usize);
    }
    if stack.is_empty() || trailing {
        out.push(b'/');
    }
    let len = out.len() - end;
    out.copy_within(end.., start);
    out.truncate(start + len);
    Some(Span::new(start, start + len))
}

/// Whether the target forwarded upstream is the client's bytes or rebuilt from the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// Forward `raw_target` unchanged (preserves S3 signatures, odd encodings).
    Original,
    /// A rewrite or strip happened: forward the percent-encoded path plus the query.
    Rebuilt,
}

#[derive(Debug)]
pub(crate) struct RequestHead {
    pub method: Method,
    pub version: Version,
    pub fields: Fields,
    method_span: Span,
    raw_target: Span,
    path: Span,
    /// Raw (still percent-encoded) query without the `?`.
    query: Option<Span>,
    /// Lowercased host without port, from Host (h1) or :authority (h2/h3).
    host: Span,
    target: Target,
}

impl Default for RequestHead {
    fn default() -> Self {
        RequestHead {
            method: Method::Get,
            version: Version::Http11,
            fields: Fields::default(),
            method_span: Span::default(),
            raw_target: Span::default(),
            path: Span::default(),
            query: None,
            host: Span::default(),
            target: Target::Original,
        }
    }
}

impl RequestHead {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets for the next request, keeping the buffer's capacity.
    pub fn clear(&mut self) {
        self.fields.clear();
        self.method = Method::Get;
        self.version = Version::Http11;
        self.method_span = Span::default();
        self.raw_target = Span::default();
        self.path = Span::default();
        self.query = None;
        self.host = Span::default();
        self.target = Target::Original;
    }

    /// The request line. `target` is origin-form (`/p?q`), absolute-form
    /// (`http://host/p?q`, whose authority becomes the host) or `*`, whose path is `/`. The
    /// path is cleaned into the buffer; the raw target is kept for forwarding.
    pub fn set_line(
        &mut self,
        method: &[u8],
        target: &[u8],
        version: Version,
    ) -> Result<(), BadPath> {
        self.method = Method::from_bytes(method);
        self.version = version;
        self.method_span = self.fields.copy(method);
        self.raw_target = self.fields.copy(target);
        let path_and_query = if target == b"*" {
            &b"/"[..]
        } else if target.first() == Some(&b'/') {
            target
        } else {
            let rest = strip_scheme(target).ok_or(BadPath)?;
            let authority_end = rest
                .iter()
                .position(|&b| b == b'/' || b == b'?')
                .unwrap_or(rest.len());
            self.set_host(&rest[..authority_end]);
            match &rest[authority_end..] {
                [] => &b"/"[..],
                [b'?', ..] => return Err(BadPath),
                p => p,
            }
        };
        let (path, query) = split_query(path_and_query);
        self.path = clean_path(path, &mut self.fields.buf).ok_or(BadPath)?;
        self.query = query.map(|q| self.fields.copy(q));
        Ok(())
    }

    /// Appends a header field (see [`Fields::push`]).
    pub fn push_field(&mut self, name: &[u8], value: &[u8]) {
        self.fields.push(name, value);
    }

    /// Sets the routing host from an authority (`Host` or `:authority`): lowercased, port and
    /// a trailing dot removed, IPv6 brackets kept.
    pub fn set_host(&mut self, authority: &[u8]) {
        let host = match authority.first() {
            Some(b'[') => authority
                .iter()
                .position(|&b| b == b']')
                .map_or(authority, |i| &authority[..=i]),
            _ => authority
                .iter()
                .position(|&b| b == b':')
                .map_or(authority, |i| &authority[..i]),
        };
        let host = host.strip_suffix(b".").unwrap_or(host);
        let start = self.fields.buf.len();
        self.fields
            .buf
            .extend(host.iter().map(u8::to_ascii_lowercase));
        self.host = Span::new(start, self.fields.buf.len());
    }

    pub fn path(&self) -> CleanPath<'_> {
        CleanPath(self.path.get(&self.fields.buf))
    }
    /// The raw query, without `?`; `None` when the target had no `?`.
    pub fn query(&self) -> Option<&[u8]> {
        self.query.map(|q| q.get(&self.fields.buf))
    }
    pub fn host(&self) -> &[u8] {
        self.host.get(&self.fields.buf)
    }
    pub fn method_bytes(&self) -> &[u8] {
        self.method_span.get(&self.fields.buf)
    }
    /// The request-target as the client sent it.
    pub fn raw_target(&self) -> &[u8] {
        self.raw_target.get(&self.fields.buf)
    }
    pub fn target(&self) -> Target {
        self.target
    }

    /// `rewrite`: `new_uri` is an expanded template, `path[?query]`. Its path is taken as
    /// already decoded (it is built from decoded pieces such as `{path}` and `{re.1}`) and only
    /// normalised; a `?` in it replaces the query, otherwise the query is kept. Marks the target
    /// [`Target::Rebuilt`].
    pub fn rewrite(&mut self, new_uri: &[u8]) -> Result<(), BadPath> {
        let (path, query) = split_query(new_uri);
        self.rewrite_parts(path, query)
    }

    /// [`rewrite`](Self::rewrite) with the path and the query apart, for a rewrite whose
    /// template says where its query starts: a `?` in `path` is a byte of the path.
    pub fn rewrite_parts(&mut self, path: &[u8], query: Option<&[u8]>) -> Result<(), BadPath> {
        let start = self.fields.buf.len();
        self.fields.buf.extend_from_slice(path);
        match normalize(&mut self.fields.buf, start) {
            Some(span) => self.path = span,
            None => {
                self.fields.buf.truncate(start);
                return Err(BadPath);
            }
        }
        if let Some(q) = query {
            self.query = Some(self.fields.copy(q));
        }
        self.target = Target::Rebuilt;
        Ok(())
    }

    /// `stripPrefix`: cuts a literal prefix at a segment boundary from the clean path (what is
    /// left starts with `/`, or is `/`). The raw target is cut too when its bytes start with the
    /// same prefix at a boundary and what is left of them cleans to the path that is left, so
    /// the forwarded target stays byte-identical past the prefix and names the path the routes
    /// saw; otherwise the target is marked rebuilt. `false` (and no change) when the path does
    /// not start with the prefix.
    pub fn strip_prefix(&mut self, prefix: &[u8]) -> bool {
        let prefix = prefix.strip_suffix(b"/").unwrap_or(prefix);
        if prefix.is_empty() {
            return true;
        }
        match strip_prefix_ignore_case(self.path.get(&self.fields.buf), prefix) {
            Some([]) => self.path = self.fields.copy(b"/"),
            Some([b'/', ..]) => self.path.start += prefix.len() as u32,
            _ => return false,
        }
        if self.target == Target::Original {
            let raw = self.raw_target.get(&self.fields.buf);
            // `/a/../a/x` cleans to `/a/x`, but its bytes past `/a` are `/../a/x`: an origin
            // would read another path than `/x`, or none.
            let keep = match strip_prefix_ignore_case(raw, prefix) {
                Some(rest @ [b'/', ..]) => {
                    cleans_to(split_query(rest).0, self.path.get(&self.fields.buf))
                }
                _ => false,
            };
            match keep {
                true => self.raw_target.start += prefix.len() as u32,
                false => self.target = Target::Rebuilt,
            }
        }
        true
    }

    /// Writes the request-target to send upstream: raw bytes if [`Target::Original`], else the
    /// percent-encoded clean path plus `?query`.
    pub fn write_upstream_target(&self, out: &mut Vec<u8>) {
        if self.target == Target::Original
            && self.raw_target.get(&self.fields.buf).first() == Some(&b'/')
        {
            out.extend_from_slice(self.raw_target());
            return;
        }
        push_encoded(out, self.path().as_bytes(), b"-._~!$&'()*+,;=:@/");
        if let Some(q) = self.query() {
            out.push(b'?');
            // A rewritten query may hold bytes a template expanded from decoded input; `%`
            // stays, so escapes already in the query are not encoded twice.
            push_encoded(out, q, b"-._~!$&'()*+,;=:@/?%");
        }
    }

    /// Fills a head from h2/h3 pseudo-headers and a header map (one copy into the buffer).
    /// Cookie crumbs are joined into one field. The routing host is `:authority`, else Host;
    /// a request with neither, or whose Host names another authority than `:authority`, is a
    /// `BadPath` (400). Without a Host field, one is added from `:authority`, so an HTTP/1.1
    /// upstream gets it.
    pub fn fill_from_http(&mut self, parts: &http::request::Parts) -> Result<(), BadPath> {
        self.clear();
        let version = match parts.version {
            http::Version::HTTP_3 => Version::H3,
            _ => Version::H2,
        };
        let target = parts.uri.path_and_query().ok_or(BadPath)?.as_str();
        self.set_line(parts.method.as_str().as_bytes(), target.as_bytes(), version)?;
        let mut host = None;
        for (name, value) in &parts.headers {
            if name == http::header::COOKIE {
                continue;
            }
            if name == http::header::HOST {
                host.get_or_insert(value.as_bytes());
            }
            self.push_field(name.as_str().as_bytes(), value.as_bytes());
        }
        let mut cookies = parts
            .headers
            .get_all(http::header::COOKIE)
            .iter()
            .peekable();
        if cookies.peek().is_some() {
            self.fields
                .push_joined(b"cookie", cookies.map(|v| v.as_bytes()), b"; ");
        }
        let authority = parts.uri.authority().map(|a| a.as_str().as_bytes());
        match (authority, host) {
            (Some(a), Some(h)) if !a.eq_ignore_ascii_case(h) => return Err(BadPath),
            (Some(a), None) => self.push_field(b"host", a),
            (None, None) => return Err(BadPath),
            _ => {}
        }
        self.set_host(authority.or(host).unwrap_or_default());
        Ok(())
    }
}

/// Appends `bytes`, percent-encoding every byte that is not ASCII alphanumeric or in `keep`.
fn push_encoded(out: &mut Vec<u8>, bytes: &[u8], keep: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || keep.contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        }
    }
}

fn strip_scheme(target: &[u8]) -> Option<&[u8]> {
    let colon = target.iter().position(|&b| b == b':')?;
    let scheme = &target[..colon];
    if !(scheme.eq_ignore_ascii_case(b"http") || scheme.eq_ignore_ascii_case(b"https")) {
        return None;
    }
    target[colon..].strip_prefix(b"://")
}

fn split_query(uri: &[u8]) -> (&[u8], Option<&[u8]>) {
    match uri.iter().position(|&b| b == b'?') {
        Some(i) => (&uri[..i], Some(&uri[i + 1..])),
        None => (uri, None),
    }
}

/// A request-target or rewrite result that cannot be made into a [`CleanPath`]; answered 400.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BadPath;

#[derive(Debug)]
pub(crate) struct ResponseHead {
    pub status: Status,
    pub fields: Fields,
    /// Tokens the negotiation layers (precompressed sidecars, encode) add to Vary after the
    /// config's header ops ran. The only writer of the `Accept-Encoding` Vary token, so a
    /// config `Vary` set can never drop it.
    pub vary_accept_encoding: bool,
}

impl ResponseHead {
    pub fn new(status: Status) -> Self {
        ResponseHead {
            status,
            fields: Fields::default(),
            vary_accept_encoding: false,
        }
    }
    pub fn clear(&mut self, status: Status) {
        self.status = status;
        self.fields.clear();
        self.vary_accept_encoding = false;
    }
    /// Converts for h2/h3 `send_response` (one HeaderMap build per response): the status and
    /// every live field except hop-by-hop ones and Content-Length. As in h1, framing comes
    /// from the body, so the driver sets `content-length` when the body's length is known. A
    /// field the `http` crate rejects (a value with CR, LF or NUL) is left out.
    pub fn to_http(&self) -> http::Response<()> {
        let mut resp = http::Response::new(());
        *resp.status_mut() =
            http::StatusCode::from_u16(self.status.code()).expect("Status is in 100..=999");
        let headers = resp.headers_mut();
        for (name, value, tag) in self.fields.live() {
            if tag.hop_by_hop() || tag == Known::ContentLength {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(name),
                http::HeaderValue::from_bytes(value),
            ) {
                headers.append(name, value);
            }
        }
        resp
    }
}

/// Path prefixes compare ASCII case-insensitively, like the `path` matcher that selects them.
/// Whether the raw path `raw` cleans to `clean`. Allocation-free once the thread's scratch
/// buffer has grown to the longest path seen.
fn cleans_to(raw: &[u8], clean: &[u8]) -> bool {
    thread_local! {
        static SCRATCH: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }
    SCRATCH.with_borrow_mut(|scratch| {
        scratch.clear();
        clean_path(raw, scratch).is_some_and(|span| span.get(scratch) == clean)
    })
}

fn strip_prefix_ignore_case<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(raw: &str) -> Option<String> {
        let mut out = b"junk".to_vec();
        let span = clean_path(raw.as_bytes(), &mut out)?;
        assert_eq!(
            span.end as usize,
            out.len(),
            "the clean path is appended at the end"
        );
        Some(String::from_utf8(span.get(&out).to_vec()).unwrap())
    }

    #[test]
    fn clean_path_resolves_dot_segments() {
        assert_eq!(clean("/").as_deref(), Some("/"));
        assert_eq!(clean("/a/b").as_deref(), Some("/a/b"));
        assert_eq!(clean("/a/./b").as_deref(), Some("/a/b"));
        assert_eq!(clean("/a/../b").as_deref(), Some("/b"));
        assert_eq!(clean("/a/b/..").as_deref(), Some("/a/"));
        assert_eq!(clean("/a/.").as_deref(), Some("/a/"));
        assert_eq!(clean("/a/..").as_deref(), Some("/"));
    }

    #[test]
    fn clean_path_merges_slashes_and_keeps_a_trailing_one() {
        assert_eq!(clean("//a///b").as_deref(), Some("/a/b"));
        assert_eq!(clean("/blog/").as_deref(), Some("/blog/"));
        assert_eq!(clean("/blog//").as_deref(), Some("/blog/"));
    }

    #[test]
    fn clean_path_decodes_before_resolving() {
        assert_eq!(clean("/a/%2e%2e/b").as_deref(), Some("/b"));
        assert_eq!(clean("/a%2F..%2Fb").as_deref(), Some("/b"));
        assert_eq!(clean("/caf%C3%A9").as_deref(), Some("/café"));
        assert_eq!(clean("/a%20b").as_deref(), Some("/a b"));
    }

    #[test]
    fn clean_path_rejects_escapes_above_the_root_and_bad_input() {
        assert_eq!(clean("/.."), None);
        assert_eq!(clean("/a/../.."), None);
        assert_eq!(clean("/%2e%2e/etc/passwd"), None);
        assert_eq!(clean("/%zz"), None);
        assert_eq!(clean("/%2"), None);
        assert_eq!(clean("a/b"), None);
        assert_eq!(clean(""), None);
    }

    #[test]
    fn clean_path_keeps_control_bytes_for_matchers() {
        assert_eq!(clean("/a%00b").as_deref(), Some("/a\0b"));
    }

    fn head(method: &str, target: &str, host: &str) -> RequestHead {
        let mut h = RequestHead::new();
        h.set_line(method.as_bytes(), target.as_bytes(), Version::Http11)
            .unwrap();
        h.push_field(b"Host", host.as_bytes());
        h.push_field(b"Accept-Encoding", b" br, gzip ");
        h.push_field(b"X-Custom", b"one");
        h.push_field(b"x-custom", b"two");
        h.set_host(host.as_bytes());
        h
    }

    #[test]
    fn request_line_and_host() {
        let h = head("GET", "/a/../b%20c?x=1&y", "Example.COM:8443");
        assert_eq!(h.method, Method::Get);
        assert_eq!(h.method_bytes(), b"GET");
        assert_eq!(h.path().as_bytes(), b"/b c");
        assert_eq!(h.query(), Some(&b"x=1&y"[..]));
        assert_eq!(h.host(), b"example.com");
        assert_eq!(h.raw_target(), b"/a/../b%20c?x=1&y");
        assert_eq!(h.target(), Target::Original);

        let h = head("PURGE", "/", "[::1]:80");
        assert_eq!(h.method, Method::Other);
        assert_eq!(h.method_bytes(), b"PURGE");
        assert_eq!(h.host(), b"[::1]");
        assert_eq!(h.query(), None);
    }

    #[test]
    fn absolute_form_sets_the_host() {
        let mut h = RequestHead::new();
        h.set_line(b"GET", b"http://Example.org:80/x?q", Version::Http11)
            .unwrap();
        assert_eq!(h.host(), b"example.org");
        assert_eq!(h.path().as_bytes(), b"/x");
        assert_eq!(h.query(), Some(&b"q"[..]));
        let mut h = RequestHead::new();
        assert_eq!(
            h.set_line(b"GET", b"ftp://x/", Version::Http11),
            Err(BadPath)
        );
    }

    #[test]
    fn fields_by_tag_and_name() {
        let mut h = head("GET", "/", "a");
        assert_eq!(h.fields.get(Known::AcceptEncoding), Some(&b"br, gzip"[..]));
        let custom = HeaderName::new("X-Custom").unwrap();
        assert_eq!(
            h.fields.values(&custom).collect::<Vec<_>>(),
            [&b"one"[..], &b"two"[..]]
        );
        h.fields.set(&custom, b"three");
        assert_eq!(
            h.fields.values(&custom).collect::<Vec<_>>(),
            [&b"three"[..]]
        );
        h.fields.remove(&custom);
        assert_eq!(h.fields.values(&custom).count(), 0);
        assert_eq!(h.path().as_bytes(), b"/", "edits leave earlier spans valid");
        h.fields.set_known(Known::Vary, b"Accept-Encoding");
        assert!(
            h.fields
                .live()
                .any(|(n, v, t)| n == b"vary" && v == b"Accept-Encoding" && t == Known::Vary)
        );
    }

    #[test]
    fn header_names_are_validated() {
        assert_eq!(
            HeaderName::new("Cache-Control").unwrap().tag,
            Known::CacheControl
        );
        assert_eq!(&*HeaderName::new("X-Thing").unwrap().name, b"x-thing");
        assert!(HeaderName::new("").is_none());
        assert!(HeaderName::new("bad name").is_none());
        assert!(HeaderName::new("bad:name").is_none());
    }

    #[test]
    fn connection_tokens() {
        let mut f = Fields::default();
        f.push(b"Connection", b"keep-alive, Upgrade");
        assert!(f.has_token(Known::Connection, b"upgrade"));
        assert!(!f.has_token(Known::Connection, b"close"));
    }

    #[test]
    fn rewrite_replaces_path_and_maybe_query() {
        let mut h = head("GET", "/blog/post.mdx?x=1", "a");
        h.rewrite(b"/_md/blog/post.md").unwrap();
        assert_eq!(h.path().as_bytes(), b"/_md/blog/post.md");
        assert_eq!(h.query(), Some(&b"x=1"[..]), "no ? keeps the query");
        assert_eq!(h.target(), Target::Rebuilt);
        h.rewrite(b"/vnc.html?autoconnect=1").unwrap();
        assert_eq!(h.query(), Some(&b"autoconnect=1"[..]));
        h.rewrite(b"/a%20b").unwrap();
        assert_eq!(
            h.path().as_bytes(),
            b"/a%20b",
            "a rewritten path is not decoded again"
        );
        assert_eq!(h.rewrite(b"/../x"), Err(BadPath));
        assert_eq!(
            h.path().as_bytes(),
            b"/a%20b",
            "a failed rewrite changes nothing"
        );
    }

    #[test]
    fn strip_prefix_ignores_ascii_case() {
        let mut h = head("GET", "/DAEMON/x?a=1", "a");
        assert!(h.strip_prefix(b"/daemon"));
        assert_eq!(h.path().as_bytes(), b"/x");
        let mut out = Vec::new();
        h.write_upstream_target(&mut out);
        assert_eq!(out, b"/x?a=1");
        assert!(!head("GET", "/daemonx", "a").strip_prefix(b"/daemon"));
    }

    #[test]
    fn strip_prefix_keeps_the_raw_target_past_the_prefix() {
        let mut h = head("GET", "/daemon/socket.io/?EIO=4&t=a%2Fb", "a");
        assert!(h.strip_prefix(b"/daemon"));
        assert_eq!(h.path().as_bytes(), b"/socket.io/");
        assert_eq!(h.target(), Target::Original);
        let mut out = Vec::new();
        h.write_upstream_target(&mut out);
        assert_eq!(out, b"/socket.io/?EIO=4&t=a%2Fb");

        let mut h = head("GET", "/daemon", "a");
        assert!(h.strip_prefix(b"/daemon/"));
        assert_eq!(h.path().as_bytes(), b"/");
        assert_eq!(h.target(), Target::Rebuilt);

        let mut h = head("GET", "/daemonx", "a");
        assert!(!h.strip_prefix(b"/daemon"), "only at a segment boundary");
        assert_eq!(h.path().as_bytes(), b"/daemonx");

        let mut h = head("GET", "/%64aemon/x", "a");
        assert!(h.strip_prefix(b"/daemon"));
        assert_eq!(
            h.target(),
            Target::Rebuilt,
            "raw bytes differ from the decoded prefix"
        );
    }

    #[test]
    fn strip_prefix_forwards_the_path_the_routes_saw() {
        for (raw, path, upstream) in [
            ("/dir/../dir/..QQYQlrtat", "/..QQYQlrtat", "/..QQYQlrtat"),
            ("/dir/../dir/x?q=1", "/x", "/x?q=1"),
            ("/dir/%2e%2e/dir/x", "/x", "/x"),
        ] {
            let mut h = head("GET", raw, "a");
            assert!(h.strip_prefix(b"/dir"), "{raw}");
            assert_eq!(h.path().as_bytes(), path.as_bytes(), "{raw}");
            assert_eq!(h.target(), Target::Rebuilt, "{raw}");
            let mut out = Vec::new();
            h.write_upstream_target(&mut out);
            assert_eq!(out, upstream.as_bytes(), "{raw}");
        }
        // Bytes past the prefix that clean to the same path are kept as the client sent them.
        for (raw, upstream) in [
            ("/dir//a%2Bb?sig=x%2F", "//a%2Bb?sig=x%2F"),
            ("/dir/./x", "/./x"),
        ] {
            let mut h = head("GET", raw, "a");
            assert!(h.strip_prefix(b"/dir"));
            assert_eq!(h.target(), Target::Original, "{raw}");
            let mut out = Vec::new();
            h.write_upstream_target(&mut out);
            assert_eq!(out, upstream.as_bytes(), "{raw}");
        }
    }

    #[test]
    fn upstream_target_is_raw_until_rebuilt() {
        let mut h = head("GET", "/nix-cache-1/a%2Bb?X-Amz-Signature=x", "a");
        let mut out = Vec::new();
        h.write_upstream_target(&mut out);
        assert_eq!(out, b"/nix-cache-1/a%2Bb?X-Amz-Signature=x");
        h.rewrite(b"/caf\xc3\xa9 x/").unwrap();
        out.clear();
        h.write_upstream_target(&mut out);
        assert_eq!(out, b"/caf%C3%A9%20x/?X-Amz-Signature=x");
    }

    #[test]
    fn clean_path_traversal_cases() {
        for raw in [
            "/%2E%2E/etc/passwd",
            "/%2e%2E/",
            "/a/%2e%2e/%2e%2e/b",
            "/..%2f",
            "/a/..%2F..%2Fb",
            "/./../x",
            "//..//x",
            "/a/b/../../../c",
            "/.%2e",
        ] {
            assert_eq!(clean(raw), None, "{raw}");
        }
        // Escapes decode once: a double-encoded or overlong dot is a name, not a dot segment.
        assert_eq!(clean("/%252e%252e/x").as_deref(), Some("/%2e%2e/x"));
        let mut out = Vec::new();
        let span = clean_path(b"/%c0%ae%c0%ae/x", &mut out).unwrap();
        assert_eq!(span.get(&out), b"/\xc0\xae\xc0\xae/x");
        assert_eq!(clean("/..;/x").as_deref(), Some("/..;/x"));
        assert_eq!(clean("/...").as_deref(), Some("/..."));
        assert_eq!(
            clean("/a\\..\\b").as_deref(),
            Some("/a\\..\\b"),
            "backslash is a name byte"
        );
        assert_eq!(clean("/a/b/%2e/./c/%2E%2E").as_deref(), Some("/a/b/"));
        let deep = "/a".repeat(40) + &"/..".repeat(40);
        assert_eq!(
            clean(&deep).as_deref(),
            Some("/"),
            "deeper than the inline stack"
        );
        assert_eq!(clean(&(deep + "/..")), None);
    }

    fn h2_parts(req: http::request::Builder) -> http::request::Parts {
        req.body(()).unwrap().into_parts().0
    }

    #[test]
    fn heads_from_h2_and_h3() {
        let parts = h2_parts(
            http::Request::builder()
                .method("POST")
                .uri("https://Files.Example:8443/a/../b%20c?x=1")
                .version(http::Version::HTTP_2)
                .header("cookie", "a=1")
                .header("accept", "*/*")
                .header("cookie", "b=2"),
        );
        let mut h = RequestHead::new();
        h.fill_from_http(&parts).unwrap();
        assert_eq!(h.method, Method::Post);
        assert_eq!(h.version, Version::H2);
        assert_eq!(h.path().as_bytes(), b"/b c");
        assert_eq!(h.query(), Some(&b"x=1"[..]));
        assert_eq!(h.raw_target(), b"/a/../b%20c?x=1");
        assert_eq!(h.host(), b"files.example");
        let fields: Vec<_> = h
            .fields
            .live()
            .map(|(n, v, _)| (n.to_vec(), v.to_vec()))
            .collect();
        assert_eq!(
            fields,
            [
                (b"accept".to_vec(), b"*/*".to_vec()),
                (b"cookie".to_vec(), b"a=1; b=2".to_vec()),
                (b"host".to_vec(), b"Files.Example:8443".to_vec()),
            ],
            "cookie crumbs are joined and Host comes from :authority"
        );

        let parts = h2_parts(
            http::Request::builder()
                .uri("/x")
                .version(http::Version::HTTP_3)
                .header("host", "B.example"),
        );
        h.fill_from_http(&parts).unwrap();
        assert_eq!(h.version, Version::H3);
        assert_eq!(h.host(), b"b.example");
        assert_eq!(h.fields.get(Known::Host), Some(&b"B.example"[..]));

        let mismatch = h2_parts(
            http::Request::builder()
                .uri("https://a.example/")
                .header("host", "b.example"),
        );
        assert_eq!(h.fill_from_http(&mismatch), Err(BadPath));
        let no_host = h2_parts(http::Request::builder().uri("/"));
        assert_eq!(h.fill_from_http(&no_host), Err(BadPath));
        let traversal = h2_parts(http::Request::builder().uri("https://a.example/../x"));
        assert_eq!(h.fill_from_http(&traversal), Err(BadPath));
    }

    #[test]
    fn response_heads_for_h2_and_h3() {
        let mut head = ResponseHead::new(Status::NOT_FOUND);
        head.fields.push(b"Content-Type", b"text/html");
        head.fields.push(b"Connection", b"close");
        head.fields.push(b"Keep-Alive", b"timeout=5");
        head.fields.push(b"Transfer-Encoding", b"chunked");
        head.fields.push(b"Content-Length", b"10");
        head.fields.push(b"Set-Cookie", b"a=1");
        head.fields.push(b"Set-Cookie", b"b=2");
        head.fields.push(b"X-Removed", b"x");
        head.fields.remove(&HeaderName::new("x-removed").unwrap());
        let resp = head.to_http();
        assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
        let mut names: Vec<_> = resp.headers().keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["content-type", "set-cookie"]);
        assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
    }

    #[test]
    fn status_text_and_bounds() {
        assert_eq!(Status::NOT_FOUND.text(), "Not Found");
        assert_eq!(Status::new(599).unwrap().text(), "");
        assert!(Status::new(99).is_none());
        assert!(Status::new(1000).is_none());
        assert!(!Status::NOT_MODIFIED.has_body());
    }
}
