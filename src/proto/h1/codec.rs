//! Sans-IO HTTP/1.1. Parsing copies the head (only the head) out of the read buffer into the
//! exchange's recycled head buffer; body bytes stay in the read buffer and are relayed from
//! there.
//!
//! Smuggling and robustness rules, all rejections answering 400 and closing:
//! - Content-Length and Transfer-Encoding together; several differing Content-Lengths;
//!   Transfer-Encoding other than exactly `chunked` as the final coding.
//! - obs-fold, bare CR, whitespace before the colon, control bytes in values (httparse).
//! - Head over `max_head_bytes` (431), more than `max_header_fields` fields (431).
//! - Chunk sizes over 16 hex digits, chunk extensions over 4 KiB, trailers over the head cap.

use crate::msg::{Method, RequestHead, ResponseHead, Status, Version};

pub(crate) struct Limits {
    pub max_head_bytes: u32,
    pub max_header_fields: u16,
}

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

#[derive(Debug)]
pub(crate) struct RequestExtra {
    pub keep_alive: bool,
    pub expect_continue: bool,
    /// `Connection: upgrade` + `Upgrade: <proto>` on a GET.
    pub upgrade: bool,
}

#[derive(Debug)]
pub(crate) struct ResponseExtra {
    pub keep_alive: bool,
}

#[derive(Debug)]
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
        todo!("400 / 431 / 505")
    }
}

/// httparse tokenises; the rest of this module decides what the tokens mean.
fn tokenize<'b>(req: &mut httparse::Request<'_, 'b>, buf: &'b [u8]) -> httparse::Result<usize> {
    todo!()
}

/// Parses a request head from `buf` into `head` (cleared first).
pub(crate) fn parse_request(
    buf: &[u8],
    limits: &Limits,
    head: &mut RequestHead,
) -> Result<Parsed<RequestExtra>, ParseError> {
    todo!()
}

/// Parses an upstream response head. `method` decides body presence (HEAD, 1xx, 204, 304).
pub(crate) fn parse_response(
    buf: &[u8],
    limits: &Limits,
    method: Method,
    head: &mut ResponseHead,
) -> Result<Parsed<ResponseExtra>, ParseError> {
    todo!()
}

/// Incremental chunked-framing tracker. Used two ways:
/// - pass-through (h1 -> h1): `scan` finds where the message ends in raw bytes that are
///   forwarded unchanged, so chunked bodies are never re-encoded;
/// - decode (h1 upstream -> h2/h3 downstream): `decode` yields data ranges.
#[derive(Debug, Default)]
pub(crate) struct Chunked {
    state: ChunkState,
    remaining_in_chunk: u64,
}

#[derive(Debug, Default)]
enum ChunkState {
    #[default]
    Size,
    Ext,
    SizeLf,
    Data,
    DataCr,
    DataLf,
    Trailer,
    Done,
}

pub(crate) enum Scan {
    /// All of the input belongs to the message; more to come.
    More,
    /// The message ends after `n` bytes of the input.
    End(usize),
}

impl Chunked {
    pub fn scan(&mut self, input: &[u8]) -> Result<Scan, ParseError> {
        todo!()
    }
    /// Data ranges within `input` go to `out`; returns how many input bytes were consumed and
    /// whether the message ended.
    pub fn decode(
        &mut self,
        input: &[u8],
        out: &mut smallvec::SmallVec<[std::ops::Range<usize>; 4]>,
    ) -> Result<(usize, bool), ParseError> {
        todo!()
    }
}

/// Body framing the h1 encoder will use downstream.
#[derive(Clone, Copy, Debug)]
pub(crate) enum OutFraming {
    Length(u64),
    /// Upstream's chunked bytes forwarded unchanged.
    ChunkedPassthrough,
    /// We produce the chunks (compressed or EOF-delimited bodies).
    Chunked,
    None,
}

/// Serialises a response head: status line, live fields, framing, `Connection: close` when not
/// keeping alive, `Date` when given. One contiguous write into `out` (the head is copied once;
/// the body never is).
#[expect(clippy::ptr_arg, reason = "the body appends to `out`")]
pub(crate) fn write_response_head(
    head: &ResponseHead,
    version: Version,
    framing: OutFraming,
    keep_alive: bool,
    date: Option<&[u8]>,
    out: &mut Vec<u8>,
) {
    todo!()
}

/// `HTTP/1.1 100 Continue\r\n\r\n`, written when the handler first reads a body whose request
/// had `Expect: 100-continue` (Expect is not forwarded).
pub(crate) const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
