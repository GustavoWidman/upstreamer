//! Sans-IO HTTP/1.1. Parsing copies the head (only the head) out of the read buffer into the
//! exchange's recycled head buffer; body bytes stay in the read buffer and are relayed from
//! there.
//!
//! Smuggling and robustness rules (RFC 9112), all rejections answering 400 and closing:
//! - Content-Length and Transfer-Encoding together; several differing Content-Lengths or one
//!   that is not 1*DIGIT; Transfer-Encoding other than exactly `chunked`, or in HTTP/1.0.
//! - A field name that becomes `content-length` or `transfer-encoding` once `_` is read as `-`
//!   (some origins normalise underscores, and would frame the body differently).
//! - obs-fold, bare CR, bare LF, whitespace before the colon, control bytes in values.
//! - HTTP/1.1 requests without exactly one Host, or with a Host that is not an authority.
//! - Head over `max_head_bytes` (431), more than `max_header_fields` fields (431).
//! - Chunk sizes over 16 hex digits, chunk extensions over 4 KiB, trailers over 32 KiB, and
//!   bare CR, bare LF or control bytes anywhere in chunk framing.
//!
//! The writers are the last step before the wire: they never emit a hop-by-hop field taken
//! from a head, always write framing themselves, and drop a field whose value holds CR, LF or
//! NUL (templates can expand decoded request bytes into values).

use crate::msg::{Fields, Known, Method, RequestHead, ResponseHead, Status, Version};
use std::mem::MaybeUninit;
use std::ops::Range;

pub(crate) struct Limits {
    pub max_head_bytes: u32,
    pub max_header_fields: u16,
}

/// Field slots on the parser's stack. `max_header_fields` above this behaves as this.
const FIELD_SLOTS: usize = 256;
const MAX_CHUNK_EXT: u32 = 4 * 1024;
const MAX_TRAILER: u32 = 32 * 1024;

/// How the body after a head is delimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    None,
    Length(u64),
    Chunked,
    /// Response only: body runs to EOF (HTTP/1.0 upstreams); the downstream connection is
    /// then re-framed (chunked to h1.1 clients, DATA to h2/h3).
    UntilClose,
}

#[derive(Debug)]
pub(crate) enum Parsed<T> {
    /// Head complete: `head_len` bytes of the buffer were the head.
    Complete {
        head_len: usize,
        framing: Framing,
        extra: T,
    },
    /// Need more bytes.
    Partial,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RequestExtra {
    pub keep_alive: bool,
    pub expect_continue: bool,
    /// `Connection: upgrade` + `Upgrade: <proto>` on an HTTP/1.1 GET.
    pub upgrade: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResponseExtra {
    pub keep_alive: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseError {
    Malformed,
    HeadTooLarge,
    TooManyFields,
    Smuggling,
    BadPath,
    UnsupportedVersion,
}

impl ParseError {
    pub fn status(&self) -> Status {
        match self {
            ParseError::Malformed | ParseError::Smuggling | ParseError::BadPath => {
                Status::BAD_REQUEST
            }
            ParseError::HeadTooLarge | ParseError::TooManyFields => Status::HEADER_FIELDS_TOO_LARGE,
            ParseError::UnsupportedVersion => Status::HTTP_VERSION_NOT_SUPPORTED,
        }
    }

    /// httparse reports any unexpected bytes where the version belongs as a version error;
    /// only a well-formed `HTTP-version` that is not 1.x gets 505.
    fn from_httparse(e: httparse::Error, buf: &[u8]) -> ParseError {
        match e {
            httparse::Error::Version if names_other_version(buf) => ParseError::UnsupportedVersion,
            httparse::Error::TooManyHeaders => ParseError::TooManyFields,
            _ => ParseError::Malformed,
        }
    }
}

/// Whether the request line is `method SP target SP HTTP/DIGIT.DIGIT` (RFC 9112 §2.3).
fn names_other_version(buf: &[u8]) -> bool {
    let line = memchr::memchr(b'\r', buf).map_or(buf, |i| &buf[..i]);
    let mut parts = line.split(|&b| b == b' ');
    let (Some(_), Some(_), Some(token), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    matches!(token, [b'H', b'T', b'T', b'P', b'/', a, b'.', b] if a.is_ascii_digit() && b.is_ascii_digit())
}

type Slots<'b> = [MaybeUninit<httparse::Header<'b>>; FIELD_SLOTS];

fn slots<'b>() -> Slots<'b> {
    [const { MaybeUninit::uninit() }; FIELD_SLOTS]
}

fn slot_count(limits: &Limits) -> usize {
    usize::from(limits.max_header_fields).min(FIELD_SLOTS)
}

/// Turns httparse's status into the head length, applying the size cap. `None` is partial.
fn head_len(
    status: httparse::Status<usize>,
    buf: &[u8],
    limits: &Limits,
) -> Result<Option<usize>, ParseError> {
    let max = limits.max_head_bytes as usize;
    match status {
        httparse::Status::Complete(n) if n > max => Err(ParseError::HeadTooLarge),
        httparse::Status::Complete(n) => Ok(Some(n)),
        httparse::Status::Partial if buf.len() >= max => Err(ParseError::HeadTooLarge),
        httparse::Status::Partial => Ok(None),
    }
}

/// httparse accepts a bare LF as a line end (RFC 9112 §2.2 allows it); a proxy must not, since
/// the origin may split lines differently.
fn crlf_only(head: &[u8]) -> Result<(), ParseError> {
    match memchr::memchr_iter(b'\n', head).any(|i| i == 0 || head[i - 1] != b'\r') {
        true => Err(ParseError::Malformed),
        false => Ok(()),
    }
}

fn version(minor: Option<u8>) -> Version {
    match minor {
        Some(0) => Version::Http10,
        _ => Version::Http11,
    }
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

/// A name that is not a framing field but reads as one with `_` taken for `-`.
fn framing_alias(name: &[u8]) -> bool {
    fn alias_of(name: &[u8], real: &[u8]) -> bool {
        name.len() == real.len()
            && name.iter().zip(real).all(|(&a, &b)| {
                let a = a.to_ascii_lowercase();
                a == b || (a == b'_' && b == b'-')
            })
    }
    memchr::memchr(b'_', name).is_some()
        && (alias_of(name, b"content-length") || alias_of(name, b"transfer-encoding"))
}

/// Copies the tokenised fields into `fields`, rejecting framing aliases.
fn copy_fields(parsed: &[httparse::Header<'_>], fields: &mut Fields) -> Result<(), ParseError> {
    for h in parsed {
        let name = h.name.as_bytes();
        if framing_alias(name) {
            return Err(ParseError::Smuggling);
        }
        fields.push(name, h.value);
    }
    Ok(())
}

/// Non-empty elements of a comma-separated field, over every field line with this tag.
fn elements(fields: &Fields, tag: Known) -> impl Iterator<Item = &[u8]> {
    fields
        .values_known(tag)
        .flat_map(|v| v.split(|&b| b == b','))
        .map(trim_ows)
        .filter(|e| !e.is_empty())
}

/// What the framing fields of a message say, before body presence is considered: `None` when
/// it has neither Transfer-Encoding nor Content-Length.
fn declared_framing(fields: &Fields, version: Version) -> Result<Option<Framing>, ParseError> {
    let has_te = fields.get(Known::TransferEncoding).is_some();
    let has_cl = fields.get(Known::ContentLength).is_some();
    if has_te {
        let mut codings = elements(fields, Known::TransferEncoding);
        let only_chunked = codings
            .next()
            .is_some_and(|c| c.eq_ignore_ascii_case(b"chunked"))
            && codings.next().is_none();
        return match !has_cl && version != Version::Http10 && only_chunked {
            true => Ok(Some(Framing::Chunked)),
            false => Err(ParseError::Smuggling),
        };
    }
    if !has_cl {
        return Ok(None);
    }
    // Content-Length is `1*DIGIT`; a list of identical values is taken as one (RFC 9110
    // §8.6), but every element must be a number.
    let mut length = None;
    let lengths = fields
        .values_known(Known::ContentLength)
        .flat_map(|v| v.split(|&b| b == b','))
        .map(trim_ows);
    for e in lengths {
        let n = parse_length(e)?;
        if length.is_some_and(|l| l != n) {
            return Err(ParseError::Smuggling);
        }
        length = Some(n);
    }
    length
        .map(|n| Some(Framing::Length(n)))
        .ok_or(ParseError::Malformed)
}

/// `1*DIGIT` that fits a `u64`.
fn parse_length(digits: &[u8]) -> Result<u64, ParseError> {
    if digits.is_empty() {
        return Err(ParseError::Malformed);
    }
    digits.iter().try_fold(0u64, |n, &d| match d {
        b'0'..=b'9' => n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(d - b'0')))
            .ok_or(ParseError::Malformed),
        _ => Err(ParseError::Malformed),
    })
}

fn keep_alive(fields: &Fields, version: Version) -> bool {
    match version {
        Version::Http10 => fields.has_token(Known::Connection, b"keep-alive"),
        _ => !fields.has_token(Known::Connection, b"close"),
    }
}

/// RFC 3986 authority characters (reg-name, IP literal, port). An empty Host is allowed.
fn valid_authority(v: &[u8]) -> bool {
    v.iter()
        .all(|&b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:[]%".contains(&b))
}

/// Parses a request head from `buf` into `head` (cleared first).
pub(crate) fn parse_request(
    buf: &[u8],
    limits: &Limits,
    head: &mut RequestHead,
) -> Result<Parsed<RequestExtra>, ParseError> {
    let mut slots = slots();
    let mut req = httparse::Request::new(&mut []);
    let status = httparse::ParserConfig::default()
        .parse_request_with_uninit_headers(&mut req, buf, &mut slots[..slot_count(limits)])
        .map_err(|e| ParseError::from_httparse(e, buf))?;
    let Some(head_len) = head_len(status, buf, limits)? else {
        return Ok(Parsed::Partial);
    };
    crlf_only(&buf[..head_len])?;
    let (Some(method), Some(target)) = (req.method, req.path) else {
        return Err(ParseError::Malformed);
    };
    let version = version(req.version);

    head.clear();
    head.set_line(method.as_bytes(), target.as_bytes(), version)
        .map_err(|_| ParseError::BadPath)?;
    copy_fields(req.headers, &mut head.fields)?;

    let origin_form = target.starts_with('/') || target == "*";
    let mut hosts = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("host"));
    match (hosts.next(), hosts.next()) {
        (_, Some(_)) => return Err(ParseError::Malformed),
        (None, None) if version == Version::Http11 => return Err(ParseError::Malformed),
        (None, _) => {}
        (Some(h), None) if !valid_authority(trim_ows(h.value)) => {
            return Err(ParseError::Malformed);
        }
        (Some(h), None) if origin_form => head.set_host(trim_ows(h.value)),
        (Some(_), None) => {}
    }
    // An absolute-form target names the host, and replaces Host (RFC 9112 §3.2.2), so the
    // origin sees the host this request was routed by. `set_line` accepted its scheme.
    if let Some((_, rest)) = target.split_once("://").filter(|_| !origin_form) {
        let authority = rest.split(['/', '?']).next().unwrap_or_default();
        if !valid_authority(authority.as_bytes()) {
            return Err(ParseError::Malformed);
        }
        head.fields.set_known(Known::Host, authority.as_bytes());
    }

    let framing = declared_framing(&head.fields, version)?.unwrap_or(Framing::None);
    let fields = &head.fields;
    let http11 = version == Version::Http11;
    let extra = RequestExtra {
        keep_alive: keep_alive(fields, version),
        expect_continue: http11
            && fields
                .get(Known::Expect)
                .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue")),
        upgrade: http11
            && head.method == Method::Get
            && fields.has_token(Known::Connection, b"upgrade")
            && fields.get(Known::Upgrade).is_some_and(|v| !v.is_empty()),
    };
    head.fields.drop_connection_named();
    Ok(Parsed::Complete {
        head_len,
        framing,
        extra,
    })
}

/// Parses an upstream response head. `method` decides body presence (HEAD, 1xx, 204, 304).
pub(crate) fn parse_response(
    buf: &[u8],
    limits: &Limits,
    method: Method,
    head: &mut ResponseHead,
) -> Result<Parsed<ResponseExtra>, ParseError> {
    let mut slots = slots();
    let mut resp = httparse::Response::new(&mut []);
    let status = httparse::ParserConfig::default()
        .parse_response_with_uninit_headers(&mut resp, buf, &mut slots[..slot_count(limits)])
        .map_err(|e| ParseError::from_httparse(e, buf))?;
    let Some(head_len) = head_len(status, buf, limits)? else {
        return Ok(Parsed::Partial);
    };
    crlf_only(&buf[..head_len])?;
    let status = resp
        .code
        .and_then(Status::new)
        .ok_or(ParseError::Malformed)?;
    let version = version(resp.version);

    head.clear(status);
    copy_fields(resp.headers, &mut head.fields)?;
    let declared = declared_framing(&head.fields, version)?;
    let framing = match method == Method::Head || !status.has_body() {
        true => Framing::None,
        false => declared.unwrap_or(Framing::UntilClose),
    };
    let extra = ResponseExtra {
        keep_alive: framing != Framing::UntilClose && keep_alive(&head.fields, version),
    };
    head.fields.drop_connection_named();
    Ok(Parsed::Complete {
        head_len,
        framing,
        extra,
    })
}

/// Incremental chunked-framing tracker (RFC 9112 §7.1). Used two ways:
/// - pass-through (h1 -> h1): `scan` finds where the message ends in raw bytes that are
///   forwarded unchanged, so chunked bodies are never re-encoded;
/// - decode (h1 upstream -> h2/h3 downstream): `decode` yields data ranges.
///
/// Both run the same state machine, so a body that scans clean decodes clean.
#[derive(Debug, Default)]
pub(crate) struct Chunked {
    state: ChunkState,
    remaining_in_chunk: u64,
    /// Size digits in `Size`, extension bytes in `Ext`, trailer bytes in the trailer states.
    count: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ChunkState {
    /// Hex digits of a chunk size.
    #[default]
    Size,
    /// After the size: whitespace and `;` extensions, up to CR.
    Ext,
    /// CR of the size line seen.
    SizeLf,
    Data,
    DataCr,
    DataLf,
    /// At the start of a trailer field line, or of the final CRLF.
    TrailerStart,
    Trailer,
    TrailerLf,
    EndLf,
    Done,
}

pub(crate) enum Scan {
    /// All of the input belongs to the message; more to come.
    More,
    /// The message ends after `n` bytes of the input.
    End(usize),
}

/// The value of a hex digit (the caller matched one).
fn hex(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => b - b'A' + 10,
    }
}

/// Bytes allowed inside a chunk extension or trailer line: HTAB, visible ASCII, obs-text.
fn field_byte(b: u8) -> bool {
    b == b'\t' || (b' '..=b'~').contains(&b) || b >= 0x80
}

impl Chunked {
    pub fn scan(&mut self, input: &[u8]) -> Result<Scan, ParseError> {
        Ok(match self.advance(input, |_| {})? {
            Some(end) => Scan::End(end),
            None => Scan::More,
        })
    }

    /// Data ranges within `input` go to `out`; returns how many input bytes were consumed and
    /// whether the message ended.
    pub fn decode(
        &mut self,
        input: &[u8],
        out: &mut smallvec::SmallVec<[Range<usize>; 4]>,
    ) -> Result<(usize, bool), ParseError> {
        Ok(match self.advance(input, |r| out.push(r))? {
            Some(end) => (end, true),
            None => (input.len(), false),
        })
    }

    pub fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    /// Runs the state machine over `input`, reporting data ranges; `Some(n)` when the message
    /// ended after `n` bytes.
    fn advance(
        &mut self,
        input: &[u8],
        mut data: impl FnMut(Range<usize>),
    ) -> Result<Option<usize>, ParseError> {
        use ChunkState::*;
        if self.state == Done {
            return Ok(Some(0));
        }
        let mut i = 0;
        while i < input.len() {
            if self.state == Data {
                let take = self.remaining_in_chunk.min((input.len() - i) as u64) as usize;
                data(i..i + take);
                i += take;
                self.remaining_in_chunk -= take as u64;
                if self.remaining_in_chunk == 0 {
                    self.state = DataCr;
                }
                continue;
            }
            let b = input[i];
            i += 1;
            self.state = match (self.state, b) {
                (Size, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F') => {
                    if self.count == 16 {
                        return Err(ParseError::Malformed);
                    }
                    self.count += 1;
                    self.remaining_in_chunk = self.remaining_in_chunk << 4 | u64::from(hex(b));
                    Size
                }
                (Size, b';' | b' ' | b'\t') if self.count > 0 => {
                    self.count = 1;
                    Ext
                }
                (Size, b'\r') if self.count > 0 => SizeLf,
                (Ext, b'\r') => SizeLf,
                (Ext, _) if field_byte(b) => {
                    self.count += 1;
                    if self.count > MAX_CHUNK_EXT {
                        return Err(ParseError::Malformed);
                    }
                    Ext
                }
                (SizeLf, b'\n') if self.remaining_in_chunk == 0 => {
                    self.count = 0;
                    TrailerStart
                }
                (SizeLf, b'\n') => Data,
                (DataCr, b'\r') => DataLf,
                (DataLf, b'\n') => {
                    self.count = 0;
                    Size
                }
                (TrailerStart, b'\r') => EndLf,
                (TrailerStart, _) if crate::msg::is_tchar(b) => self.trailer_byte(Trailer)?,
                (Trailer, b'\r') => self.trailer_byte(TrailerLf)?,
                (Trailer, _) if field_byte(b) => self.trailer_byte(Trailer)?,
                (TrailerLf, b'\n') => self.trailer_byte(TrailerStart)?,
                (EndLf, b'\n') => {
                    self.state = Done;
                    return Ok(Some(i));
                }
                _ => return Err(ParseError::Malformed),
            };
        }
        Ok(None)
    }

    fn trailer_byte(&mut self, next: ChunkState) -> Result<ChunkState, ParseError> {
        self.count += 1;
        match self.count > MAX_TRAILER {
            true => Err(ParseError::Malformed),
            false => Ok(next),
        }
    }
}

/// Body framing the h1 encoder writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutFraming {
    Length(u64),
    /// Upstream's chunked bytes forwarded unchanged.
    ChunkedPassthrough,
    /// We produce the chunks (compressed or EOF-delimited bodies).
    Chunked,
    /// No body and no framing field (HEAD, statuses without content).
    None,
}

fn push_decimal(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

fn push_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(b"\r\n");
}

/// Writes the head's fields that may cross this hop: no hop-by-hop field, no Content-Length
/// (framing is written from the body), none tagged `also_skip`, and no value that would break
/// the field line.
fn push_end_to_end(out: &mut Vec<u8>, fields: &Fields, also_skip: Option<Known>) {
    for (name, value, tag) in fields.live() {
        if tag.hop_by_hop()
            || tag == Known::ContentLength
            || Some(tag) == also_skip
            || memchr::memchr3(b'\r', b'\n', 0, value).is_some()
        {
            continue;
        }
        push_field(out, name, value);
    }
}

/// `Connection: upgrade` and the head's Upgrade fields, for a 101 or an upgrade request.
fn push_upgrade(out: &mut Vec<u8>, fields: &Fields) {
    out.extend_from_slice(b"connection: upgrade\r\n");
    for value in fields.values_known(Known::Upgrade) {
        push_field(out, b"upgrade", value);
    }
}

fn push_framing(out: &mut Vec<u8>, framing: OutFraming) {
    match framing {
        OutFraming::Length(n) => {
            out.extend_from_slice(b"content-length: ");
            push_decimal(out, n);
            out.extend_from_slice(b"\r\n");
        }
        OutFraming::Chunked | OutFraming::ChunkedPassthrough => {
            out.extend_from_slice(b"transfer-encoding: chunked\r\n");
        }
        OutFraming::None => {}
    }
}

/// Serialises a response head: status line, live end-to-end fields, framing, `Connection`,
/// `Date` when given (replacing any Date in the head). One contiguous write into `out` (the
/// head is copied once; the body never is).
///
/// `version` is the client's. The status line always says HTTP/1.1 (RFC 9110 §2.5), but an
/// HTTP/1.0 client gets no chunked framing: a chunked body is then written close-delimited,
/// decoded by the caller, with `Connection: close`. A 101 carries `Connection: upgrade` and
/// the head's Upgrade fields instead of framing. 1xx, 204 and 304 never get framing fields.
pub(crate) fn write_response_head(
    head: &ResponseHead,
    version: Version,
    framing: OutFraming,
    keep_alive: bool,
    date: Option<&[u8]>,
    out: &mut Vec<u8>,
) {
    let status = head.status;
    out.extend_from_slice(b"HTTP/1.1 ");
    push_decimal(out, u64::from(status.code()));
    out.push(b' ');
    out.extend_from_slice(status.text().as_bytes());
    out.extend_from_slice(b"\r\n");
    push_end_to_end(out, &head.fields, date.map(|_| Known::Date));
    if status == Status::SWITCHING_PROTOCOLS {
        push_upgrade(out, &head.fields);
    } else {
        let chunked = matches!(
            framing,
            OutFraming::Chunked | OutFraming::ChunkedPassthrough
        );
        let close_delimited = chunked && version == Version::Http10;
        if status.has_body() && !close_delimited {
            push_framing(out, framing);
        }
        if !keep_alive || close_delimited {
            out.extend_from_slice(b"connection: close\r\n");
        } else if version == Version::Http10 {
            out.extend_from_slice(b"connection: keep-alive\r\n");
        }
    }
    if let Some(date) = date {
        push_field(out, b"date", date);
    }
    out.extend_from_slice(b"\r\n");
}

/// Serialises an upstream request head: `method target HTTP/1.1`, live end-to-end fields
/// except Expect (100-continue is answered here, never forwarded), framing, and for an upgrade
/// `Connection: upgrade` with the client's Upgrade fields. The target is
/// [`RequestHead::write_upstream_target`]'s. HTTP/1.1 needs a Host, so a head without one
/// (an HTTP/1.0 client) sends the routing host, which is empty for such a client. Callers
/// apply the proxy's header edits to `head.fields` first.
pub(crate) fn write_request_head(
    head: &RequestHead,
    framing: OutFraming,
    upgrade: bool,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(head.method_bytes());
    out.push(b' ');
    head.write_upstream_target(out);
    out.extend_from_slice(b" HTTP/1.1\r\n");
    if head.fields.get(Known::Host).is_none() {
        push_field(out, b"host", head.host());
    }
    push_end_to_end(out, &head.fields, Some(Known::Expect));
    if upgrade {
        push_upgrade(out, &head.fields);
    }
    push_framing(out, framing);
    out.extend_from_slice(b"\r\n");
}

/// `HTTP/1.1 100 Continue\r\n\r\n`, written when the handler first reads a body whose request
/// had `Expect: 100-continue` (Expect is not forwarded).
pub(crate) const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use smallvec::SmallVec;

    const LIMITS: Limits = Limits {
        max_head_bytes: 8 * 1024,
        max_header_fields: 16,
    };

    fn req(raw: &[u8]) -> Result<(RequestHead, usize, Framing, RequestExtra), ParseError> {
        let mut head = RequestHead::new();
        match parse_request(raw, &LIMITS, &mut head)? {
            Parsed::Complete {
                head_len,
                framing,
                extra,
            } => Ok((head, head_len, framing, extra)),
            Parsed::Partial => panic!("partial: {:?}", String::from_utf8_lossy(raw)),
        }
    }

    fn req_err(raw: &[u8]) -> ParseError {
        match req(raw) {
            Err(e) => e,
            Ok(_) => panic!("accepted: {:?}", String::from_utf8_lossy(raw)),
        }
    }

    fn framing_of(raw: &[u8]) -> Result<Framing, ParseError> {
        req(raw).map(|(_, _, f, _)| f)
    }

    fn resp(
        raw: &[u8],
        method: Method,
    ) -> Result<(ResponseHead, usize, Framing, bool), ParseError> {
        let mut head = ResponseHead::new(Status::OK);
        match parse_response(raw, &LIMITS, method, &mut head)? {
            Parsed::Complete {
                head_len,
                framing,
                extra,
            } => Ok((head, head_len, framing, extra.keep_alive)),
            Parsed::Partial => panic!("partial: {:?}", String::from_utf8_lossy(raw)),
        }
    }

    fn fields(f: &Fields) -> Vec<(String, String)> {
        f.live()
            .map(|(n, v, _)| {
                (
                    String::from_utf8_lossy(n).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn request_line_fields_and_head_length() {
        let raw = b"GET /a/../b?x=1 HTTP/1.1\r\nHost: Example.com:443\r\nAccept:  */* \r\n\r\nBODY";
        let (head, len, framing, extra) = req(raw).unwrap();
        assert_eq!(len, raw.len() - 4, "the body is not part of the head");
        assert_eq!(head.method, Method::Get);
        assert_eq!(head.raw_target(), b"/a/../b?x=1");
        assert_eq!(head.path().as_bytes(), b"/b");
        assert_eq!(head.query(), Some(&b"x=1"[..]));
        assert_eq!(head.host(), b"example.com");
        assert_eq!(
            fields(&head.fields),
            [
                ("host".into(), "Example.com:443".into()),
                ("accept".into(), "*/*".into())
            ]
        );
        assert_eq!(
            framing,
            Framing::None,
            "no CL or TE: no body (RFC 9112 §6.3)"
        );
        assert_eq!(
            extra,
            RequestExtra {
                keep_alive: true,
                expect_continue: false,
                upgrade: false
            }
        );
    }

    #[test]
    fn incomplete_heads_are_partial() {
        let raw = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        for cut in 0..raw.len() {
            let mut head = RequestHead::new();
            assert!(
                matches!(
                    parse_request(&raw[..cut], &LIMITS, &mut head),
                    Ok(Parsed::Partial)
                ),
                "{cut} bytes"
            );
        }
    }

    #[test]
    fn pipelined_requests_parse_one_at_a_time() {
        let raw = b"GET /1 HTTP/1.1\r\nHost: a\r\n\r\nGET /2 HTTP/1.1\r\nHost: b\r\n\r\n";
        let (_, len, _, _) = req(raw).unwrap();
        let (second, len2, _, _) = req(&raw[len..]).unwrap();
        assert_eq!(len + len2, raw.len());
        assert_eq!(second.path().as_bytes(), b"/2");
        assert_eq!(second.host(), b"b");
    }

    #[test]
    fn a_reused_head_holds_only_the_last_request() {
        let mut head = RequestHead::new();
        parse_request(
            b"GET /x HTTP/1.1\r\nHost: a\r\nX-One: 1\r\n\r\n",
            &LIMITS,
            &mut head,
        )
        .unwrap();
        parse_request(b"PUT /y HTTP/1.1\r\nHost: b\r\n\r\n", &LIMITS, &mut head).unwrap();
        assert_eq!(head.method, Method::Put);
        assert_eq!(head.path().as_bytes(), b"/y");
        assert_eq!(fields(&head.fields), [("host".into(), "b".into())]);
    }

    #[test]
    fn empty_lines_before_the_request_line_are_ignored() {
        // RFC 9112 §2.2: a server SHOULD ignore at least one empty line before the request.
        let (head, len, _, _) = req(b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(head.host(), b"a");
        assert_eq!(len, 31);
    }

    #[test]
    fn host_rules() {
        // RFC 9112 §3.2: 400 for an HTTP/1.1 request without Host, with two, or an invalid one.
        assert_eq!(req_err(b"GET / HTTP/1.1\r\n\r\n"), ParseError::Malformed);
        assert_eq!(
            req_err(b"GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n"),
            ParseError::Malformed
        );
        assert_eq!(
            req_err(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n"),
            ParseError::Malformed
        );
        assert_eq!(
            req_err(b"GET / HTTP/1.1\r\nHost: a/b\r\n\r\n"),
            ParseError::Malformed
        );
        let (head, ..) = req(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(head.host(), b"", "HTTP/1.0 may omit Host");
        let (head, ..) = req(b"GET / HTTP/1.1\r\nHost:\r\n\r\n").unwrap();
        assert_eq!(head.host(), b"", "an empty Host is valid");
        let (head, ..) = req(b"GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n").unwrap();
        assert_eq!(head.host(), b"[::1]");
    }

    #[test]
    fn an_absolute_form_target_names_the_host() {
        // RFC 9112 §3.2.2: the target's authority replaces Host.
        let (head, ..) =
            req(b"GET http://Target.example:8080/p?q HTTP/1.1\r\nHost: other.example\r\n\r\n")
                .unwrap();
        assert_eq!(head.host(), b"target.example");
        assert_eq!(head.path().as_bytes(), b"/p");
        let mut out = Vec::new();
        write_request_head(&head, OutFraming::None, false, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /p?q HTTP/1.1\r\nhost: Target.example:8080\r\n\r\n"
        );
    }

    #[test]
    fn an_absolute_form_authority_must_be_valid() {
        assert_eq!(
            req_err(b"GET http://a`b/ HTTP/1.1\r\nHost: a\r\n\r\n"),
            ParseError::Malformed
        );
    }

    #[test]
    fn a_url_in_the_query_is_not_a_host() {
        let (head, ..) = req(b"GET /r?u=http://evil.example/ HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(head.host(), b"a");
        assert_eq!(head.fields.get(Known::Host), Some(&b"a"[..]));
    }

    #[test]
    fn http10_requests_get_a_host_upstream() {
        let (head, ..) = req(b"GET /x HTTP/1.0\r\nX-A: 1\r\n\r\n").unwrap();
        let mut out = Vec::new();
        write_request_head(&head, OutFraming::None, false, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /x HTTP/1.1\r\nhost: \r\nx-a: 1\r\n\r\n"
        );
    }

    #[test]
    fn targets_that_are_not_clean_paths() {
        assert_eq!(
            req_err(b"GET /.. HTTP/1.1\r\nHost: a\r\n\r\n"),
            ParseError::BadPath
        );
        assert_eq!(
            req_err(b"GET /%zz HTTP/1.1\r\nHost: a\r\n\r\n"),
            ParseError::BadPath
        );
        assert_eq!(
            req_err(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n"),
            ParseError::BadPath,
            "authority-form is not served"
        );
        let (head, ..) = req(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(head.path().as_bytes(), b"/");
        assert_eq!(head.raw_target(), b"*");
    }

    #[test]
    fn content_length_framing() {
        let h = |cl: &str| format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {cl}\r\n\r\n");
        assert_eq!(framing_of(h("0").as_bytes()), Ok(Framing::Length(0)));
        assert_eq!(framing_of(h("42").as_bytes()), Ok(Framing::Length(42)));
        assert_eq!(framing_of(h("007").as_bytes()), Ok(Framing::Length(7)));
        assert_eq!(
            framing_of(h("18446744073709551615").as_bytes()),
            Ok(Framing::Length(u64::MAX))
        );
        // RFC 9110 §8.6: a list of identical values may be taken as one.
        assert_eq!(framing_of(h("42, 42").as_bytes()), Ok(Framing::Length(42)));
        assert_eq!(
            framing_of(
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\ncontent-length: 5\r\n\r\n"
            ),
            Ok(Framing::Length(5))
        );
    }

    #[test]
    fn invalid_content_lengths_are_rejected() {
        let h = |cl: &str| format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {cl}\r\n\r\n");
        for cl in [
            "",
            "+5",
            "-1",
            "0x10",
            "1 2",
            "1.0",
            "5,",
            ",5",
            "abc",
            "18446744073709551616",
        ] {
            assert_eq!(
                framing_of(h(cl).as_bytes()).map_err(|e| e.status()),
                Err(Status::BAD_REQUEST),
                "{cl:?}"
            );
        }
        assert_eq!(framing_of(h("5, 6").as_bytes()), Err(ParseError::Smuggling));
        assert_eq!(
            framing_of(
                b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"
            ),
            Err(ParseError::Smuggling)
        );
    }

    #[test]
    fn transfer_encoding_framing() {
        let h = |te: &str| format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: {te}\r\n\r\n");
        assert_eq!(framing_of(h("chunked").as_bytes()), Ok(Framing::Chunked));
        assert_eq!(framing_of(h("Chunked").as_bytes()), Ok(Framing::Chunked));
        assert_eq!(
            framing_of(h("chunked ,").as_bytes()),
            Ok(Framing::Chunked),
            "empty list elements are ignored"
        );
    }

    /// Request smuggling corpus: every message here frames its body ambiguously or in a way an
    /// origin may read differently, and must be refused before anything is forwarded.
    #[test]
    fn smuggling_corpus_is_refused() {
        let corpus: &[&[u8]] = &[
            // CL.TE and TE.CL
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n",
            // TE obfuscations
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \"chunked\"\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked;q=1\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: \x0bchunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\x00\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding : chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding\t: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\n Transfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nX: y\r\n\tTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer_Encoding: chunked\r\nContent-Length: 4\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent_Length: 4\r\n\r\n",
            // TE in HTTP/1.0 (RFC 9112 §6.1: faulty framing)
            b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n",
            // Differing and malformed Content-Length
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 50\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5, 50\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 0x5\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\x00\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length : 5\r\n\r\n",
            // Line endings: bare LF, bare CR
            b"POST / HTTP/1.1\nHost: a\nContent-Length: 5\n\n",
            b"POST / HTTP/1.1\r\nHost: a\nContent-Length: 5\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\n",
            b"POST / HTTP/1.1\r\nHost: a\rContent-Length: 5\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nX: a\rb\r\n\r\n",
            // NUL and control bytes
            b"POST / HTTP/1.1\r\nHost: a\r\nX: a\x00b\r\n\r\n",
            b"POST /\x00 HTTP/1.1\r\nHost: a\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\x00\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: a\r\nX: \x7f\r\n\r\n",
            // Request line games
            b"POST  / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"POST / HTTP/1.1 \r\nHost: a\r\n\r\n",
            b"POST /a b HTTP/1.1\r\nHost: a\r\n\r\n",
            // Two Hosts (the routing host and the forwarded one could differ)
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
        ];
        for raw in corpus {
            let e = req_err(raw);
            assert_eq!(
                e.status(),
                Status::BAD_REQUEST,
                "{:?}: {e:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    #[test]
    fn versions() {
        let (head, ..) = req(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(head.version, Version::Http10);
        for raw in [
            &b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..],
            b"GET / HTTP/1.2\r\nHost: a\r\n\r\n",
            b"GET / HTTP/3.0\r\nHost: a\r\n\r\n",
        ] {
            assert_eq!(req_err(raw).status(), Status::HTTP_VERSION_NOT_SUPPORTED);
        }
    }

    #[test]
    fn head_size_and_field_count_limits() {
        let limits = Limits {
            max_head_bytes: 64,
            max_header_fields: 3,
        };
        let mut head = RequestHead::new();
        let fits = b"GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\n\r\n";
        assert!(matches!(
            parse_request(fits, &limits, &mut head),
            Ok(Parsed::Complete { .. })
        ));
        let long = format!("GET /{} HTTP/1.1\r\nHost: a\r\n\r\n", "x".repeat(40));
        assert!(matches!(
            parse_request(long.as_bytes(), &limits, &mut head),
            Err(ParseError::HeadTooLarge)
        ));
        let unfinished = format!("GET /{}", "x".repeat(70));
        assert!(
            matches!(
                parse_request(unfinished.as_bytes(), &limits, &mut head),
                Err(ParseError::HeadTooLarge)
            ),
            "a head that cannot end within the cap is refused before it ends"
        );
        let many = b"GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\nC: 3\r\n\r\n";
        let e = parse_request(many, &limits, &mut head).unwrap_err();
        assert_eq!(e, ParseError::TooManyFields);
        assert_eq!(e.status(), Status::HEADER_FIELDS_TOO_LARGE);
    }

    #[test]
    fn keep_alive_by_version() {
        // RFC 9112 §9.3: 1.1 persists unless "close"; 1.0 only with "keep-alive".
        let ka = |raw: &[u8]| req(raw).unwrap().3.keep_alive;
        assert!(ka(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"));
        assert!(!ka(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: Close\r\n\r\n"
        ));
        assert!(!ka(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: foo, close\r\n\r\n"
        ));
        assert!(!ka(b"GET / HTTP/1.0\r\n\r\n"));
        assert!(ka(b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n"));
    }

    #[test]
    fn expect_continue() {
        let ex = |raw: &[u8]| req(raw).unwrap().3.expect_continue;
        assert!(ex(
            b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-Continue\r\nContent-Length: 1\r\n\r\n"
        ));
        assert!(!ex(
            b"PUT / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n"
        ));
        // RFC 9110 §10.1.1: a 100-continue expectation in HTTP/1.0 is ignored.
        assert!(!ex(
            b"PUT / HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n"
        ));
    }

    #[test]
    fn upgrade_requests() {
        let up = |raw: &[u8]| req(raw).unwrap().3.upgrade;
        assert!(up(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"));
        assert!(
            !up(b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n"),
            "Connection must list upgrade"
        );
        assert!(!up(
            b"POST /ws HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        ));
        // RFC 9110 §7.8: Upgrade in an HTTP/1.0 request is ignored.
        assert!(!up(
            b"GET /ws HTTP/1.0\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"
        ));
    }

    #[test]
    fn fields_named_by_connection_do_not_cross_the_hop() {
        let (head, ..) = req(
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: X-Secret, host, upgrade, close\r\nX-Secret: 1\r\nX-Kept: 2\r\nClose: 3\r\nUpgrade: h2c\r\n\r\n",
        )
        .unwrap();
        let names: Vec<_> = fields(&head.fields).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["host", "connection", "x-kept", "close", "upgrade"]);
    }

    #[test]
    fn response_framing() {
        // RFC 9112 §6.3, in rule order.
        let f = |raw: &[u8], m: Method| resp(raw, m).map(|(_, _, f, ka)| (f, ka));
        let ok_cl = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        assert_eq!(f(ok_cl, Method::Get), Ok((Framing::Length(5), true)));
        assert_eq!(
            f(ok_cl, Method::Head),
            Ok((Framing::None, true)),
            "HEAD responses have no body"
        );
        for status in [
            "100 Continue",
            "101 Switching Protocols",
            "103 Early Hints",
            "204 No Content",
            "304 Not Modified",
        ] {
            let raw = format!("HTTP/1.1 {status}\r\nContent-Length: 5\r\n\r\n");
            assert_eq!(
                f(raw.as_bytes(), Method::Get).unwrap().0,
                Framing::None,
                "{status}"
            );
        }
        assert_eq!(
            f(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                Method::Get
            ),
            Ok((Framing::Chunked, true))
        );
        assert_eq!(
            f(b"HTTP/1.1 200 OK\r\n\r\n", Method::Get),
            Ok((Framing::UntilClose, false)),
            "no framing: read to close, never reused"
        );
        assert_eq!(
            f(b"HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", Method::Get),
            Ok((Framing::Length(1), false))
        );
        assert_eq!(
            f(
                b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\n",
                Method::Get
            ),
            Ok((Framing::Length(1), true))
        );
        assert_eq!(
            f(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\n",
                Method::Get
            ),
            Ok((Framing::Length(1), false))
        );
    }

    #[test]
    fn response_heads() {
        let raw = b"HTTP/1.1 404 Nope\r\nContent-Type: text/plain\r\nX-Note: caf\xc3\xa9\r\nContent-Length: 0\r\n\r\nNEXT";
        let (head, len, ..) = resp(raw, Method::Get).unwrap();
        assert_eq!(len, raw.len() - 4);
        assert_eq!(head.status, Status::NOT_FOUND);
        assert_eq!(
            head.fields.get(Known::ContentType),
            Some(&b"text/plain"[..])
        );
        assert_eq!(head.fields.live().count(), 3);
        let mut head = ResponseHead::new(Status::OK);
        assert!(matches!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nA: 1\r\n",
                &LIMITS,
                Method::Get,
                &mut head
            ),
            Ok(Parsed::Partial)
        ));
    }

    #[test]
    fn response_smuggling_corpus_is_refused() {
        let corpus: &[&[u8]] = &[
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer_Encoding: chunked\r\nContent-Length: 4\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\r\n folded\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\n",
            b"HTTP/1.1 200 OK\nContent-Length: 5\n\n",
            b"HTTP/1.1 200 OK\r\nX: a\rContent-Length: 5\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: \x00\r\n\r\n",
            b"HTTP/1.1 099 Low\r\n\r\n",
            b"HTTP/1.1 20 OK\r\n\r\n",
        ];
        for raw in corpus {
            assert!(
                resp(raw, Method::Get).is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
    }

    fn scan_all(chunks: &[&[u8]]) -> Result<Option<usize>, ParseError> {
        let mut c = Chunked::default();
        let mut offset = 0;
        for chunk in chunks {
            if let Scan::End(n) = c.scan(chunk)? {
                return Ok(Some(offset + n));
            }
            offset += chunk.len();
        }
        Ok(None)
    }

    fn decode_all(body: &[u8]) -> Result<(Vec<u8>, usize), ParseError> {
        let mut c = Chunked::default();
        let mut ranges = SmallVec::new();
        let (used, ended) = c.decode(body, &mut ranges)?;
        assert!(ended, "{:?}", String::from_utf8_lossy(body));
        Ok((
            ranges
                .iter()
                .flat_map(|r| body[r.clone()].to_vec())
                .collect(),
            used,
        ))
    }

    #[test]
    fn chunked_bodies_end_where_the_last_chunk_ends() {
        let body = b"5\r\nhello\r\nA;name=\"v\"\r\n0123456789\r\n0\r\n\r\nNEXT";
        assert_eq!(scan_all(&[body]), Ok(Some(body.len() - 4)));
        let (data, used) = decode_all(body).unwrap();
        assert_eq!(data, b"hello0123456789");
        assert_eq!(used, body.len() - 4);
        let split: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(scan_all(&split), Ok(Some(body.len() - 4)), "byte at a time");
    }

    #[test]
    fn chunked_trailers_and_extensions() {
        for body in [
            &b"0\r\n\r\n"[..],
            b"000\r\n\r\n",
            b"0;last\r\n\r\n",
            b"0\r\nX-Checksum: abc\r\nX-Two: 2\r\n\r\n",
            b"3 ;ext\r\nabc\r\n0\r\n\r\n",
            b"3\t;a=b;c\r\nabc\r\n0\r\n\r\n",
            b"3 \r\nabc\r\n0\r\n\r\n",
            b"ffffffffffffffff",
        ] {
            let mut c = Chunked::default();
            assert!(c.scan(body).is_ok(), "{:?}", String::from_utf8_lossy(body));
        }
        assert_eq!(
            decode_all(b"3;x=y\r\nabc\r\n0\r\nT: 1\r\n\r\n").unwrap().0,
            b"abc"
        );
    }

    /// Chunk framing that an origin or client could split differently, or that overflows.
    #[test]
    fn chunked_smuggling_corpus_is_refused() {
        let ext = format!("1;{}\r\na\r\n0\r\n\r\n", "x".repeat(4 * 1024 + 1));
        let trailer = format!("0\r\nX: {}\r\n\r\n", "x".repeat(32 * 1024));
        let corpus: &[&[u8]] = &[
            b"10000000000000000\r\n",
            b"fffffffffffffffff\r\n",
            b"\r\n",
            b";ext\r\n",
            b"x\r\n",
            b"-1\r\n",
            b"0x5\r\nhello\r\n0\r\n\r\n",
            b"+5\r\nhello\r\n0\r\n\r\n",
            b"5\nhello\r\n0\r\n\r\n",
            b"5\r\nhello\n0\r\n\r\n",
            b"5\r\nhelloX\r\n0\r\n\r\n",
            b"5\r\nhello\r\r\n0\r\n\r\n",
            b"5\rhello\r\n0\r\n\r\n",
            b"5;a\nb\r\nhello\r\n",
            b"5;a\x00\r\nhello\r\n",
            b"5;a\rb\r\nhello\r\n",
            b"0\r\n\n",
            b"0\r\nX: 1\n\r\n",
            b"0\r\n X: folded\r\n\r\n",
            b"0\r\nX: a\x00\r\n\r\n",
            b"0\r\n:x\r\n\r\n",
            ext.as_bytes(),
            trailer.as_bytes(),
        ];
        for body in corpus {
            assert_eq!(
                scan_all(&[body]),
                Err(ParseError::Malformed),
                "{:?}",
                String::from_utf8_lossy(&body[..body.len().min(40)])
            );
        }
    }

    fn response_bytes(
        head: &ResponseHead,
        version: Version,
        framing: OutFraming,
        keep_alive: bool,
        date: Option<&[u8]>,
    ) -> String {
        let mut out = Vec::new();
        write_response_head(head, version, framing, keep_alive, date, &mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn response_heads_on_the_wire() {
        let mut head = ResponseHead::new(Status::OK);
        head.fields.push(b"Content-Type", b"text/html");
        head.fields.push(b"Connection", b"keep-alive");
        head.fields.push(b"Keep-Alive", b"timeout=5");
        head.fields.push(b"Transfer-Encoding", b"chunked");
        head.fields.push(b"Content-Length", b"999");
        head.fields.push(b"Upgrade", b"h2c");
        head.fields.push(b"Date", b"old");
        head.fields.push(b"X-Bad", b"a\r\nSet-Cookie: x=1");
        assert_eq!(
            response_bytes(
                &head,
                Version::Http11,
                OutFraming::Length(12),
                true,
                Some(b"Sat, 14 Nov 2026 12:00:00 GMT")
            ),
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: 12\r\ndate: Sat, 14 Nov 2026 12:00:00 GMT\r\n\r\n"
        );
        assert_eq!(
            response_bytes(&head, Version::Http11, OutFraming::Chunked, false, None),
            "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ndate: old\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
        );
    }

    #[test]
    fn http10_clients_get_no_chunked_framing() {
        let head = ResponseHead::new(Status::OK);
        assert_eq!(
            response_bytes(
                &head,
                Version::Http10,
                OutFraming::ChunkedPassthrough,
                true,
                None
            ),
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n"
        );
        assert_eq!(
            response_bytes(&head, Version::Http10, OutFraming::Length(3), true, None),
            "HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: keep-alive\r\n\r\n"
        );
    }

    #[test]
    fn statuses_without_content_get_no_framing() {
        for status in [Status::NO_CONTENT, Status::NOT_MODIFIED, Status::CONTINUE] {
            let head = ResponseHead::new(status);
            let wire = response_bytes(&head, Version::Http11, OutFraming::Length(0), true, None);
            assert!(!wire.contains("content-length"), "{wire}");
        }
        let head = ResponseHead::new(Status::new(599).unwrap());
        assert_eq!(
            response_bytes(&head, Version::Http11, OutFraming::Length(0), true, None),
            "HTTP/1.1 599 \r\ncontent-length: 0\r\n\r\n",
            "unknown codes keep the SP before the empty reason"
        );
    }

    #[test]
    fn switching_protocols_keeps_upgrade() {
        let mut head = ResponseHead::new(Status::SWITCHING_PROTOCOLS);
        head.fields.push(b"Connection", b"Upgrade");
        head.fields.push(b"Upgrade", b"websocket");
        head.fields
            .push(b"Sec-WebSocket-Accept", b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(
            response_bytes(&head, Version::Http11, OutFraming::None, true, None),
            "HTTP/1.1 101 Switching Protocols\r\nsec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n"
        );
    }

    #[test]
    fn upstream_request_heads_on_the_wire() {
        let (head, ..) = req(
            b"PUT /a%2Fb?x HTTP/1.1\r\nHost: a.example\r\nExpect: 100-continue\r\nTE: trailers\r\nTransfer-Encoding: chunked\r\nX-Kept: 1\r\n\r\n",
        )
        .unwrap();
        let mut out = Vec::new();
        write_request_head(&head, OutFraming::ChunkedPassthrough, false, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "PUT /a%2Fb?x HTTP/1.1\r\nhost: a.example\r\nx-kept: 1\r\ntransfer-encoding: chunked\r\n\r\n"
        );

        let (head, ..) = req(
            b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n",
        )
        .unwrap();
        let mut out = Vec::new();
        write_request_head(&head, OutFraming::None, true, &mut out);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "GET /ws HTTP/1.1\r\nhost: a\r\nsec-websocket-key: k\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n"
        );
    }

    #[test]
    fn a_rewritten_query_cannot_inject_into_the_request_line() {
        let (mut head, ..) = req(b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n").unwrap();
        head.rewrite(b"/y?q=a b\r\nX: 1&z=%41").unwrap();
        let mut out = Vec::new();
        write_request_head(&head, OutFraming::None, false, &mut out);
        assert!(
            out.starts_with(b"GET /y?q=a%20b%0D%0AX:%201&z=%41 HTTP/1.1\r\n"),
            "{}",
            String::from_utf8_lossy(&out)
        );
    }

    fn token() -> impl Strategy<Value = String> {
        "[a-z0-9][a-z0-9-]{0,12}".prop_map(|s| format!("x-{s}"))
    }

    fn value() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(
            prop_oneof![Just(b' '), Just(b'\t'), 0x21u8..=0x7e, 0x80u8..=0xff],
            0..24,
        )
        .prop_map(|v| trim_ows(&v).to_vec())
    }

    fn out_framing() -> impl Strategy<Value = OutFraming> {
        prop_oneof![
            Just(OutFraming::None),
            Just(OutFraming::Chunked),
            any::<u64>().prop_map(OutFraming::Length),
        ]
    }

    fn end_to_end(f: &Fields) -> Vec<(Vec<u8>, Vec<u8>)> {
        f.live()
            .filter(|&(_, _, t)| !t.hop_by_hop() && t != Known::ContentLength)
            .map(|(n, v, _)| (n.to_vec(), v.to_vec()))
            .collect()
    }

    proptest! {
        /// Whatever head the proxy builds, the bytes it sends upstream parse back to the same
        /// request with the same framing.
        #[test]
        fn upstream_requests_round_trip(
            method in prop_oneof![Just("GET".to_string()), Just("POST".to_string()), "[A-Z]{1,10}"],
            segments in proptest::collection::vec("[a-zA-Z0-9._~-]{1,8}|%[0-9A-F]{2}", 0..6),
            query in proptest::option::of("[a-zA-Z0-9=&%/?:@]{0,20}"),
            host in "[a-z0-9.-]{1,20}(:[0-9]{1,5})?",
            extra in proptest::collection::vec((token(), value()), 0..10),
            framing in out_framing(),
        ) {
            let mut target = String::new();
            for s in &segments {
                target.push('/');
                target.push_str(s);
            }
            if target.is_empty() {
                target.push('/');
            }
            if let Some(q) = &query {
                target.push('?');
                target.push_str(q);
            }
            let mut built = RequestHead::new();
            prop_assume!(built.set_line(method.as_bytes(), target.as_bytes(), Version::Http11).is_ok());
            built.push_field(b"Host", host.as_bytes());
            for (n, v) in &extra {
                built.push_field(n.as_bytes(), v);
            }
            built.set_host(host.as_bytes());

            let mut wire = Vec::new();
            write_request_head(&built, framing, false, &mut wire);
            let (parsed, len, parsed_framing, _) = req(&wire).unwrap();
            prop_assert_eq!(len, wire.len());
            prop_assert_eq!(parsed.method_bytes(), built.method_bytes());
            prop_assert_eq!(parsed.raw_target(), built.raw_target());
            prop_assert_eq!(parsed.path(), built.path());
            prop_assert_eq!(parsed.query(), built.query());
            prop_assert_eq!(parsed.host(), built.host());
            prop_assert_eq!(end_to_end(&parsed.fields), end_to_end(&built.fields));
            let expected = match framing {
                OutFraming::Length(n) => Framing::Length(n),
                OutFraming::Chunked | OutFraming::ChunkedPassthrough => Framing::Chunked,
                OutFraming::None => Framing::None,
            };
            prop_assert_eq!(parsed_framing, expected);
        }

        /// A response head written for an HTTP/1.1 client parses back to the same status,
        /// fields, framing and persistence.
        #[test]
        fn responses_round_trip(
            code in 100u16..=999,
            fields_in in proptest::collection::vec((token(), value()), 0..10),
            framing in out_framing(),
            keep_alive in any::<bool>(),
        ) {
            let status = Status::new(code).unwrap();
            prop_assume!(status != Status::SWITCHING_PROTOCOLS);
            let mut built = ResponseHead::new(status);
            for (n, v) in &fields_in {
                built.fields.push(n.as_bytes(), v);
            }
            let mut wire = Vec::new();
            write_response_head(&built, Version::Http11, framing, keep_alive, None, &mut wire);
            let (parsed, len, parsed_framing, parsed_keep_alive) = resp(&wire, Method::Get).unwrap();
            prop_assert_eq!(len, wire.len());
            prop_assert_eq!(parsed.status, status);
            prop_assert_eq!(end_to_end(&parsed.fields), end_to_end(&built.fields));
            let expected = match (status.has_body(), framing) {
                (false, _) => Framing::None,
                (true, OutFraming::Length(n)) => Framing::Length(n),
                (true, OutFraming::Chunked | OutFraming::ChunkedPassthrough) => Framing::Chunked,
                (true, OutFraming::None) => Framing::UntilClose,
            };
            prop_assert_eq!(parsed_framing, expected);
            prop_assert_eq!(parsed_keep_alive, keep_alive && expected != Framing::UntilClose);
        }

        /// Chunked encoding of any data, split anywhere: the scan ends exactly at the end of
        /// the message and decoding yields the data.
        #[test]
        fn chunked_round_trip(
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..64), 0..8),
            ext in proptest::option::of("[a-z]{1,8}(=[a-z0-9]{1,8})?"),
            trailers in proptest::collection::vec((token(), value()), 0..3),
            cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..6),
        ) {
            let mut body = Vec::new();
            let mut data = Vec::new();
            for c in &chunks {
                body.extend_from_slice(format!("{:x}", c.len()).as_bytes());
                if let Some(e) = &ext {
                    body.push(b';');
                    body.extend_from_slice(e.as_bytes());
                }
                body.extend_from_slice(b"\r\n");
                body.extend_from_slice(c);
                body.extend_from_slice(b"\r\n");
                data.extend_from_slice(c);
            }
            body.extend_from_slice(b"0\r\n");
            for (n, v) in &trailers {
                push_field(&mut body, n.as_bytes(), v);
            }
            body.extend_from_slice(b"\r\n");
            let end = body.len();
            body.extend_from_slice(b"GET / HTTP/1.1\r\n");

            let mut points: Vec<usize> = cuts.iter().map(|i| i.index(body.len())).collect();
            points.sort_unstable();
            let mut pieces = Vec::new();
            let mut last = 0;
            for p in points {
                pieces.push(&body[last..p]);
                last = p;
            }
            pieces.push(&body[last..]);
            prop_assert_eq!(scan_all(&pieces), Ok(Some(end)));

            let mut c = Chunked::default();
            let mut decoded = Vec::new();
            let mut offset = 0;
            for piece in &pieces {
                let mut ranges = SmallVec::new();
                let (used, ended) = c.decode(piece, &mut ranges).unwrap();
                for r in ranges {
                    decoded.extend_from_slice(&piece[r]);
                }
                offset += used;
                if ended {
                    break;
                }
            }
            prop_assert_eq!(offset, end);
            prop_assert_eq!(decoded, data);
        }
    }
}
