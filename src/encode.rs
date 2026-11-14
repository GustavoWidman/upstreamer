//! Dynamic compression (`encode` steps). Decided once per response, in `pipeline::finalize`'s
//! caller, from the request's `encode` set and the response head:
//! skip when the client accepts none of the set, the response already has Content-Encoding,
//! has `Cache-Control: no-transform`, is not compressible, is shorter than 512 bytes (when the
//! length is known), is a 204/304/HEAD/206, or is `text/event-stream`.
//!
//! Streaming: each input chunk is compressed and flushed as it comes (zstd `flush`, gzip sync
//! flush), so a slow stream is never held back. Immutable files are compressed once per core
//! and cached in the catalog instead.
//!
//! Compressor contexts are large (zstd level 3 holds about 3 MiB, deflate about 300 KiB), so
//! each core keeps a few idle ones per coding and a stream takes one instead of allocating.

use crate::body::Body;
use crate::config::EncodingName;
use crate::msg::{Known, Method, RequestHead, ResponseHead, Status};
use bytes::{Bytes, BytesMut};
use flate2::{Compress, Compression, FlushCompress};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::io;
use zstd::zstd_safe::zstd_sys::ZSTD_EndDirective;
use zstd::zstd_safe::{CCtx, InBuffer, OutBuffer, ResetDirective};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Br = 0,
    Zstd = 1,
    Gzip = 2,
}

impl From<EncodingName> for Encoding {
    fn from(name: EncodingName) -> Encoding {
        match name {
            EncodingName::Br => Encoding::Br,
            EncodingName::Zstd => Encoding::Zstd,
            EncodingName::Gzip => Encoding::Gzip,
        }
    }
}

impl Encoding {
    pub fn token(self) -> &'static [u8] {
        match self {
            Encoding::Br => b"br",
            Encoding::Zstd => b"zstd",
            Encoding::Gzip => b"gzip",
        }
    }
    /// Sidecar file extension for precompressed files.
    pub fn sidecar(self) -> &'static [u8] {
        match self {
            Encoding::Br => b".br",
            Encoding::Zstd => b".zst",
            Encoding::Gzip => b".gz",
        }
    }
    /// Whether a response can be compressed with it on the fly. Brotli is served only from
    /// precompressed sidecars.
    fn dynamic(self) -> bool {
        matches!(self, Encoding::Zstd | Encoding::Gzip)
    }
}

/// Encodings allowed for dynamic compression, in preference order (at most 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EncodingSet {
    order: [Option<Encoding>; 3],
}

impl EncodingSet {
    /// The set in the given preference order; a repeated encoding keeps its first position.
    pub fn new(list: impl IntoIterator<Item = Encoding>) -> EncodingSet {
        let mut set = EncodingSet::default();
        let mut n = 0;
        for e in list {
            if n < set.order.len() && !set.order[..n].contains(&Some(e)) {
                set.order[n] = Some(e);
                n += 1;
            }
        }
        set
    }
    pub fn is_empty(&self) -> bool {
        self.order[0].is_none()
    }
    /// In preference order.
    pub fn iter(&self) -> impl Iterator<Item = Encoding> + '_ {
        self.order.iter().map_while(|e| *e)
    }
}

/// Responses with a known length below this are sent as they are: the coding's framing
/// would eat most of the gain.
const MIN_LENGTH: u64 = 512;

/// Whether and how to compress a response dynamically. `None` when the client accepts none of
/// `set`, or the response must not be compressed (see the module docs). Pure; called once per
/// response by the pipeline, after `finalize`.
pub(crate) fn decide(
    set: EncodingSet,
    req: &RequestHead,
    head: &ResponseHead,
    len: Option<u64>,
) -> Option<Encoding> {
    if set.is_empty()
        || req.method == Method::Head
        || !head.status.has_body()
        || head.status == Status::PARTIAL_CONTENT
        || len.is_some_and(|n| n < MIN_LENGTH)
        || head.fields.get(Known::ContentEncoding).is_some()
        || head.fields.has_token(Known::CacheControl, b"no-transform")
        || !head
            .fields
            .get(Known::ContentType)
            .is_some_and(compressible)
    {
        return None;
    }
    let offered: SmallVec<[Encoding; 3]> = set.iter().collect();
    crate::files::negotiate::pick_encoding(
        req.fields.get(Known::AcceptEncoding),
        &offered,
        Encoding::dynamic,
    )
}

/// Whether a Content-Type names a media type worth compressing: text (except event streams,
/// which must reach the client unbuffered and are left to the origin), the structured-syntax
/// `+json` and `+xml` types, and the uncompressed application, image and font formats.
fn compressible(content_type: &[u8]) -> bool {
    let essence = content_type
        .split(|&b| b == b';')
        .next()
        .unwrap_or_default()
        .trim_ascii();
    let Some(slash) = essence.iter().position(|&b| b == b'/') else {
        return false;
    };
    let (kind, subtype) = (&essence[..slash], &essence[slash + 1..]);
    let is = |a: &[u8], b: &[u8]| a.eq_ignore_ascii_case(b);
    let ends = |suffix: &[u8]| {
        subtype.len() > suffix.len()
            && subtype[subtype.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };
    if is(kind, b"text") {
        return !is(subtype, b"event-stream");
    }
    if ends(b"+json") || ends(b"+xml") {
        return true;
    }
    const APPLICATION: &[&[u8]] = &[
        b"json",
        b"javascript",
        b"x-javascript",
        b"ecmascript",
        b"xml",
        b"wasm",
        b"x-ndjson",
        b"graphql",
        b"vnd.ms-fontobject",
        b"x-font-ttf",
        b"x-font-opentype",
        b"rtf",
        b"x-sh",
        b"x-tar",
        b"x-yaml",
        b"yaml",
        b"toml",
    ];
    const IMAGE: &[&[u8]] = &[b"bmp", b"x-icon", b"vnd.microsoft.icon"];
    const FONT: &[&[u8]] = &[b"ttf", b"otf", b"collection"];
    let table: &[&[u8]] = if is(kind, b"application") {
        APPLICATION
    } else if is(kind, b"image") {
        IMAGE
    } else if is(kind, b"font") {
        FONT
    } else {
        return false;
    };
    table.iter().any(|t| is(subtype, t))
}

/// Wraps `body` in a compressor for `encoding`, and edits `head` to match: sets
/// Content-Encoding, drops Content-Length, keeps a strong ETag from validating the encoded
/// bytes as if they were the identity ones, and sets `vary_accept_encoding`.
///
/// A body already in memory is compressed here in one frame, so it keeps an exact length;
/// any other body is compressed chunk by chunk as it is read. `head` and `body` are left as
/// they were when no compressor can be had (brotli, or a failed context allocation).
pub(crate) fn wrap(encoding: Encoding, body: Body, head: &mut ResponseHead) -> Body {
    let Some(mut encoder) = Encoder::take(encoding) else {
        return body;
    };
    let body = match body {
        Body::Empty => match encoder.whole(&[]) {
            Ok(bytes) => Body::Bytes(bytes),
            Err(_) => return Body::Empty,
        },
        Body::Bytes(identity) => match encoder.whole(&identity) {
            Ok(bytes) => Body::Bytes(bytes),
            Err(_) => return Body::Bytes(identity),
        },
        inner => Body::Encoded(Box::new(EncodedBody { inner, encoder })),
    };
    encoded_head(encoding, head);
    body
}

fn encoded_head(encoding: Encoding, head: &mut ResponseHead) {
    head.fields
        .set_known(Known::ContentEncoding, encoding.token());
    head.fields.remove_known(Known::ContentLength);
    if let Some(etag) = head.fields.get(Known::ETag)
        && !etag.starts_with(b"W/")
    {
        let mut weak: SmallVec<[u8; 96]> = SmallVec::new();
        weak.extend_from_slice(b"W/");
        weak.extend_from_slice(etag);
        head.fields.set_known(Known::ETag, &weak);
    }
    // Byte ranges would address the identity representation, not the encoded bytes sent.
    let fields = &mut head.fields;
    for field in fields.table.iter_mut().filter(|f| f.live) {
        if field.tag == Known::Other && field.name.get(&fields.buf) == b"accept-ranges" {
            field.live = false;
        }
    }
    head.vary_accept_encoding = true;
}

/// Idle compressors kept per core and per coding. Bounds the memory a burst of compressed
/// streams leaves behind (about 3 MiB per zstd context) while keeping steady traffic
/// allocation-free.
const IDLE_PER_CODING: usize = 4;

thread_local! {
    static IDLE: RefCell<Idle> = const {
        RefCell::new(Idle { zstd: Vec::new(), gzip: Vec::new() })
    };
}

struct Idle {
    zstd: Vec<(CCtx<'static>, BytesMut)>,
    gzip: Vec<(Compress, BytesMut)>,
}

const GZIP_LEVEL: u32 = 5;

enum Codec {
    Zstd(CCtx<'static>),
    Gzip(Compress),
    /// The final frame was produced; the context went back to the idle list.
    Finished,
}

/// Streaming compressor state. zstd at its default level 3, whose window for a stream of
/// unknown length is 2 MiB, under the 8 MiB cap HTTP decoders may enforce (RFC 9659); gzip
/// level 5; br only from sidecars.
///
/// Output is written into one `BytesMut` and split off per chunk, so once a chunk has been
/// written and dropped, the next one reuses its memory.
pub(crate) struct Encoder {
    codec: Codec,
    out: BytesMut,
}

impl Encoder {
    /// A compressor in its initial state, from this core's idle list when it has one. `None`
    /// for brotli, or when zstd cannot allocate a context.
    fn take(encoding: Encoding) -> Option<Encoder> {
        let reused = IDLE.with_borrow_mut(|idle| match encoding {
            Encoding::Zstd => idle.zstd.pop().map(|(c, out)| (Codec::Zstd(c), out)),
            Encoding::Gzip => idle.gzip.pop().map(|(c, out)| (Codec::Gzip(c), out)),
            Encoding::Br => None,
        });
        let (mut codec, out) = match (reused, encoding) {
            (Some(reused), _) => reused,
            (None, Encoding::Zstd) => (Codec::Zstd(CCtx::try_create()?), BytesMut::new()),
            (None, Encoding::Gzip) => (
                Codec::Gzip(Compress::new_gzip(Compression::new(GZIP_LEVEL), 15)),
                BytesMut::new(),
            ),
            (None, Encoding::Br) => return None,
        };
        match &mut codec {
            Codec::Zstd(cctx) => {
                cctx.reset(ResetDirective::SessionOnly).ok()?;
            }
            Codec::Gzip(deflate) => deflate.reset(),
            Codec::Finished => {}
        }
        Some(Encoder { codec, out })
    }

    /// Compresses `input` and flushes, so the returned bytes decode to all of `input`.
    fn chunk(&mut self, input: &[u8]) -> io::Result<Bytes> {
        self.run(input, Flush::Block)?;
        Ok(self.out.split().freeze())
    }

    /// Ends the stream; the returned bytes close the frame. The compressor goes back to the
    /// idle list, and every later call fails.
    fn finish(&mut self) -> io::Result<Bytes> {
        self.end(&[])
    }

    /// A complete stream holding `input`, in one frame.
    fn whole(&mut self, input: &[u8]) -> io::Result<Bytes> {
        self.end(input)
    }

    fn end(&mut self, input: &[u8]) -> io::Result<Bytes> {
        self.run(input, Flush::End)?;
        let bytes = self.out.split().freeze();
        self.release();
        Ok(bytes)
    }

    fn finished(&self) -> bool {
        matches!(self.codec, Codec::Finished)
    }

    fn run(&mut self, input: &[u8], flush: Flush) -> io::Result<()> {
        let mut room = input.len() + input.len() / 16 + 64;
        match &mut self.codec {
            Codec::Zstd(cctx) => {
                let directive = match flush {
                    Flush::Block => ZSTD_EndDirective::ZSTD_e_flush,
                    Flush::End => ZSTD_EndDirective::ZSTD_e_end,
                };
                let mut input = InBuffer::around(input);
                loop {
                    let start = grow(&mut self.out, room);
                    let mut output = OutBuffer::around(&mut self.out[start..]);
                    let pending = cctx
                        .compress_stream2(&mut output, &mut input, directive)
                        .map_err(zstd_error)?;
                    let written = output.pos();
                    self.out.truncate(start + written);
                    if pending == 0 {
                        return Ok(());
                    }
                    room *= 2;
                }
            }
            Codec::Gzip(deflate) => {
                let flush = match flush {
                    Flush::Block => FlushCompress::Sync,
                    Flush::End => FlushCompress::Finish,
                };
                let mut rest = input;
                loop {
                    let start = grow(&mut self.out, room);
                    let (read, written) = (deflate.total_in(), deflate.total_out());
                    let status = deflate
                        .compress(rest, &mut self.out[start..], flush)
                        .map_err(io::Error::other)?;
                    let written = (deflate.total_out() - written) as usize;
                    rest = &rest[(deflate.total_in() - read) as usize..];
                    self.out.truncate(start + written);
                    let done = match flush {
                        FlushCompress::Finish => status == flate2::Status::StreamEnd,
                        _ => rest.is_empty() && written < room,
                    };
                    if done {
                        return Ok(());
                    }
                    room *= 2;
                }
            }
            Codec::Finished => Err(io::Error::other("compressed stream already finished")),
        }
    }

    /// Hands the context and the output buffer to this core's idle list. The buffer keeps
    /// whatever allocation the chunks already split off it still share.
    fn release(&mut self) {
        let mut out = std::mem::take(&mut self.out);
        out.clear();
        let codec = std::mem::replace(&mut self.codec, Codec::Finished);
        // `try_with`: an encoder dropped while the thread's locals are torn down just frees.
        let _ = IDLE.try_with(|idle| {
            let mut idle = idle.borrow_mut();
            match codec {
                Codec::Zstd(cctx) if idle.zstd.len() < IDLE_PER_CODING => {
                    idle.zstd.push((cctx, out))
                }
                Codec::Gzip(deflate) if idle.gzip.len() < IDLE_PER_CODING => {
                    idle.gzip.push((deflate, out))
                }
                _ => {}
            }
        });
    }
}

impl Drop for Encoder {
    /// A stream dropped before its end (client gone, upstream failed) still returns its
    /// compressor; `take` resets it.
    fn drop(&mut self) {
        self.release();
    }
}

#[derive(Clone, Copy)]
enum Flush {
    /// Everything given so far becomes decodable.
    Block,
    /// The stream ends.
    End,
}

/// Extends `out` by `room` writable bytes and returns where they start. Reuses the buffer's
/// allocation when every chunk split off it has been dropped.
fn grow(out: &mut BytesMut, room: usize) -> usize {
    let start = out.len();
    out.resize(start + room, 0);
    start
}

fn zstd_error(code: usize) -> io::Error {
    io::Error::other(zstd::zstd_safe::get_error_name(code))
}

pub(crate) struct EncodedBody {
    pub inner: Body,
    pub encoder: Encoder,
}

impl EncodedBody {
    /// The next compressed chunk: reads one chunk of `inner`, compresses it and flushes, so
    /// every input chunk produces output before the next read. `None` after the final frame.
    pub async fn next_chunk(&mut self, core: &crate::runtime::Core) -> io::Result<Option<Bytes>> {
        loop {
            if self.encoder.finished() {
                return Ok(None);
            }
            match self.inner.next_chunk(core).await? {
                Some(chunk) if chunk.is_empty() => continue,
                Some(chunk) => return self.encoder.chunk(&chunk).map(Some),
                None => return self.encoder.finish().map(Some),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::Version;
    use std::io::Read;
    use zstd::zstd_safe::{DCtx, DParameter};

    use Encoding::{Br, Gzip, Zstd};

    #[test]
    fn encoding_set_keeps_order_and_drops_repeats() {
        let set = EncodingSet::new([Encoding::Zstd, Encoding::Gzip, Encoding::Zstd]);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [Encoding::Zstd, Encoding::Gzip]
        );
        assert!(EncodingSet::new([]).is_empty());
    }

    fn request(method: &str, accept: Option<&str>) -> RequestHead {
        let mut req = RequestHead::new();
        req.set_line(method.as_bytes(), b"/", Version::Http11)
            .unwrap();
        req.push_field(b"Host", b"example.com");
        if let Some(accept) = accept {
            req.push_field(b"Accept-Encoding", accept.as_bytes());
        }
        req.set_host(b"example.com");
        req
    }

    fn response(status: u16, fields: &[(&str, &str)]) -> ResponseHead {
        let mut head = ResponseHead::new(Status::new(status).unwrap());
        for (name, value) in fields {
            head.fields.push(name.as_bytes(), value.as_bytes());
        }
        head
    }

    fn html() -> ResponseHead {
        response(200, &[("Content-Type", "text/html; charset=utf-8")])
    }

    #[test]
    fn negotiation_follows_q_values_then_config_order() {
        let zstd_gzip = EncodingSet::new([Zstd, Gzip]);
        let gzip_zstd = EncodingSet::new([Gzip, Zstd]);
        let cases: &[(EncodingSet, Option<&str>, Option<Encoding>)] = &[
            (zstd_gzip, None, None),
            (zstd_gzip, Some(""), None),
            (zstd_gzip, Some("gzip"), Some(Gzip)),
            (zstd_gzip, Some("zstd"), Some(Zstd)),
            (zstd_gzip, Some("gzip, deflate, br, zstd"), Some(Zstd)),
            (gzip_zstd, Some("gzip, deflate, br, zstd"), Some(Gzip)),
            (zstd_gzip, Some("zstd;q=0.5, gzip"), Some(Gzip)),
            (zstd_gzip, Some("zstd;q=0.9, gzip;q=0.8"), Some(Zstd)),
            (zstd_gzip, Some("zstd;q=0, gzip"), Some(Gzip)),
            (zstd_gzip, Some("zstd;q=0, gzip;q=0"), None),
            (zstd_gzip, Some("*"), Some(Zstd)),
            (zstd_gzip, Some("*;q=0"), None),
            (zstd_gzip, Some("zstd;q=0, *"), Some(Gzip)),
            (zstd_gzip, Some("identity"), None),
            (zstd_gzip, Some("deflate, br"), None),
            (zstd_gzip, Some("x-gzip"), Some(Gzip)),
            (zstd_gzip, Some("GZIP"), Some(Gzip)),
            (zstd_gzip, Some("gzip;Q=1.0"), Some(Gzip)),
            (EncodingSet::new([Gzip]), Some("zstd, gzip"), Some(Gzip)),
            (EncodingSet::new([Br, Gzip]), Some("br, gzip"), Some(Gzip)),
            (EncodingSet::new([Br]), Some("br"), None),
            (EncodingSet::new([]), Some("zstd, gzip"), None),
        ];
        for &(set, accept, want) in cases {
            let got = decide(set, &request("GET", accept), &html(), Some(4096));
            assert_eq!(got, want, "set {set:?}, Accept-Encoding {accept:?}");
        }
    }

    #[test]
    fn eligibility_matrix() {
        let set = EncodingSet::new([Zstd, Gzip]);
        let get = request("GET", Some("zstd, gzip"));
        let head = request("HEAD", Some("zstd, gzip"));
        let ct = |v: &str| response(200, &[("Content-Type", v)]);
        let with = |extra: (&str, &str)| response(200, &[("Content-Type", "text/html"), extra]);
        let cases: &[(&str, &RequestHead, ResponseHead, Option<u64>, bool)] = &[
            ("html of unknown length", &get, html(), None, true),
            ("html at the minimum length", &get, html(), Some(512), true),
            (
                "html below the minimum length",
                &get,
                html(),
                Some(511),
                false,
            ),
            ("empty body", &get, html(), Some(0), false),
            ("HEAD", &head, html(), Some(4096), false),
            (
                "404 page",
                &get,
                response(404, &[("Content-Type", "text/html")]),
                None,
                true,
            ),
            (
                "502 page",
                &get,
                response(502, &[("Content-Type", "text/plain")]),
                None,
                true,
            ),
            (
                "204",
                &get,
                response(204, &[("Content-Type", "text/html")]),
                None,
                false,
            ),
            (
                "304",
                &get,
                response(304, &[("Content-Type", "text/html")]),
                None,
                false,
            ),
            (
                "206",
                &get,
                response(206, &[("Content-Type", "text/html")]),
                None,
                false,
            ),
            (
                "101",
                &get,
                response(101, &[("Content-Type", "text/html")]),
                None,
                false,
            ),
            (
                "already gzip",
                &get,
                with(("Content-Encoding", "gzip")),
                None,
                false,
            ),
            (
                "already br",
                &get,
                with(("Content-Encoding", "br")),
                None,
                false,
            ),
            (
                "no-transform",
                &get,
                with(("Cache-Control", "public, No-Transform")),
                None,
                false,
            ),
            (
                "other cache-control",
                &get,
                with(("Cache-Control", "no-cache, max-age=0")),
                None,
                true,
            ),
            ("no content type", &get, response(200, &[]), None, false),
            ("event stream", &get, ct("text/event-stream"), None, false),
            (
                "event stream with params",
                &get,
                ct("Text/Event-Stream; charset=utf-8"),
                None,
                false,
            ),
            ("css", &get, ct("text/css"), None, true),
            (
                "json with params",
                &get,
                ct("Application/JSON; charset=utf-8"),
                None,
                true,
            ),
            ("javascript", &get, ct("application/javascript"), None, true),
            ("ndjson", &get, ct("application/x-ndjson"), None, true),
            (
                "structured +json",
                &get,
                ct("application/vnd.api+json"),
                None,
                true,
            ),
            (
                "manifest",
                &get,
                ct("application/manifest+json"),
                None,
                true,
            ),
            (
                "structured +xml",
                &get,
                ct("application/rss+xml"),
                None,
                true,
            ),
            ("svg", &get, ct("image/svg+xml"), None, true),
            ("wasm", &get, ct("application/wasm"), None, true),
            ("font", &get, ct("font/ttf"), None, true),
            ("png", &get, ct("image/png"), None, false),
            ("jpeg", &get, ct("image/jpeg"), None, false),
            ("woff2", &get, ct("font/woff2"), None, false),
            ("zip", &get, ct("application/zip"), None, false),
            (
                "octet stream",
                &get,
                ct("application/octet-stream"),
                None,
                false,
            ),
            ("video", &get, ct("video/mp4"), None, false),
            (
                "bare +json suffix",
                &get,
                ct("application/+json"),
                None,
                false,
            ),
            ("malformed type", &get, ct("texthtml"), None, false),
        ];
        for (name, req, resp, len, compress) in cases {
            let got = decide(set, req, resp, *len);
            assert_eq!(got.is_some(), *compress, "{name}");
        }
    }

    #[test]
    fn wrap_edits_the_head_for_the_encoded_representation() {
        let mut head = response(
            200,
            &[
                ("Content-Type", "text/html"),
                ("Content-Length", "2048"),
                ("ETag", "\"abc\""),
                ("Accept-Ranges", "bytes"),
                ("Cache-Control", "max-age=60"),
            ],
        );
        let body = wrap(Gzip, Body::Bytes(Bytes::from(vec![b'a'; 2048])), &mut head);
        let fields: Vec<(&[u8], &[u8])> = head.fields.live().map(|(n, v, _)| (n, v)).collect();
        assert_eq!(
            fields,
            [
                (&b"content-type"[..], &b"text/html"[..]),
                (b"cache-control", b"max-age=60"),
                (b"content-encoding", b"gzip"),
                (b"etag", b"W/\"abc\""),
            ]
        );
        assert!(head.vary_accept_encoding);
        let Body::Bytes(encoded) = body else {
            panic!("a body in memory stays in memory")
        };
        assert_eq!(gunzip(&encoded), vec![b'a'; 2048]);
    }

    #[test]
    fn wrap_keeps_a_weak_etag_and_replaces_content_encoding() {
        let mut head = response(200, &[("Content-Type", "text/html"), ("ETag", "W/\"v1\"")]);
        let body = wrap(Zstd, Body::Bytes(Bytes::from_static(b"hello")), &mut head);
        assert_eq!(head.fields.get(Known::ETag), Some(&b"W/\"v1\""[..]));
        assert_eq!(head.fields.get(Known::ContentEncoding), Some(&b"zstd"[..]));
        let Body::Bytes(encoded) = body else {
            panic!("a body in memory stays in memory")
        };
        assert_eq!(unzstd(&encoded), b"hello");
    }

    #[test]
    fn wrap_with_brotli_leaves_the_response_untouched() {
        let mut head = response(
            200,
            &[("Content-Type", "text/html"), ("Content-Length", "5")],
        );
        let body = wrap(Br, Body::Bytes(Bytes::from_static(b"hello")), &mut head);
        assert_eq!(head.fields.get(Known::ContentLength), Some(&b"5"[..]));
        assert_eq!(head.fields.get(Known::ContentEncoding), None);
        assert!(!head.vary_accept_encoding);
        assert!(matches!(body, Body::Bytes(b) if b == "hello"));
    }

    fn gunzip(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(data)
            .read_to_end(&mut out)
            .expect("valid gzip, CRC and length included");
        out
    }

    fn unzstd(data: &[u8]) -> Vec<u8> {
        zstd::stream::decode_all(data).expect("valid zstd")
    }

    /// Incremental reference decoders: `feed` returns everything decodable from the bytes
    /// given so far, `ended` whether the stream's final frame was seen whole.
    enum Decoder {
        Zstd(DCtx<'static>, bool),
        Gzip(flate2::Decompress, bool),
    }

    impl Decoder {
        fn new(encoding: Encoding) -> Decoder {
            match encoding {
                Zstd => {
                    let mut dctx = DCtx::create();
                    // RFC 9659: HTTP recipients may refuse windows above 8 MiB.
                    dctx.set_parameter(DParameter::WindowLogMax(23)).unwrap();
                    Decoder::Zstd(dctx, false)
                }
                Gzip => Decoder::Gzip(flate2::Decompress::new_gzip(15), false),
                Br => unreachable!(),
            }
        }

        fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
            let mut out: Vec<u8> = Vec::with_capacity(chunk.len() * 8 + 1024);
            match self {
                Decoder::Zstd(dctx, ended) => {
                    let mut input = InBuffer::around(chunk);
                    loop {
                        out.reserve(64 * 1024);
                        let mut output = OutBuffer::around(&mut out);
                        let hint = dctx.decompress_stream(&mut output, &mut input).unwrap();
                        let full = output.pos() == output.capacity();
                        *ended = hint == 0;
                        if input.pos() == chunk.len() && !full {
                            return out;
                        }
                    }
                }
                Decoder::Gzip(inflate, ended) => {
                    let mut rest = chunk;
                    loop {
                        out.reserve(64 * 1024);
                        let before = inflate.total_in();
                        let status = inflate
                            .decompress_vec(rest, &mut out, flate2::FlushDecompress::Sync)
                            .unwrap();
                        rest = &rest[(inflate.total_in() - before) as usize..];
                        *ended = status == flate2::Status::StreamEnd;
                        if *ended || (rest.is_empty() && out.len() < out.capacity()) {
                            assert!(rest.is_empty(), "no bytes after the gzip trailer");
                            return out;
                        }
                    }
                }
            }
        }

        fn ended(&self) -> bool {
            match self {
                Decoder::Zstd(_, ended) | Decoder::Gzip(_, ended) => *ended,
            }
        }
    }

    fn event(i: usize) -> Vec<u8> {
        format!("{{\"seq\":{i},\"status\":\"running\",\"host\":\"lab\",\"load\":[0.4,0.3,0.2]}}\n")
            .into_bytes()
    }

    #[test]
    fn every_chunk_of_a_slow_stream_decodes_before_the_next_is_fed() {
        for encoding in [Zstd, Gzip] {
            let mut encoder = Encoder::take(encoding).unwrap();
            let mut decoder = Decoder::new(encoding);
            let mut wire = Vec::new();
            for i in 0..200 {
                let chunk = encoder.chunk(&event(i)).unwrap();
                assert!(
                    !chunk.is_empty(),
                    "{encoding:?}: event {i} produced no bytes"
                );
                wire.extend_from_slice(&chunk);
                assert_eq!(
                    decoder.feed(&chunk),
                    event(i),
                    "{encoding:?}: event {i} decodes from the bytes sent so far"
                );
            }
            let last = encoder.finish().unwrap();
            assert_eq!(
                decoder.feed(&last),
                b"",
                "{encoding:?}: the end adds no data"
            );
            assert!(
                decoder.ended(),
                "{encoding:?}: the final frame closes the stream"
            );
            wire.extend_from_slice(&last);
            let all: Vec<u8> = (0..200).flat_map(event).collect();
            let decoded = match encoding {
                Zstd => unzstd(&wire),
                _ => gunzip(&wire),
            };
            assert_eq!(decoded, all, "{encoding:?}: the whole stream decodes");
            assert!(
                encoder.chunk(b"late").is_err(),
                "{encoding:?}: a finished stream takes no more input"
            );
        }
    }

    /// Deterministic text-like data: words from a small vocabulary picked by an LCG, so it
    /// compresses like markup rather than like zeros.
    fn text(len: usize, seed: u64) -> Vec<u8> {
        const WORDS: &[&[u8]] = &[
            b"<div class=\"post\">",
            b"</div>",
            b"upstreamer ",
            b"proxy ",
            b"the ",
            b"\n",
            b"<a href=\"/blog/",
            b"\">",
            b"</a>",
            b"nix ",
            b"store ",
            b"0123456789 ",
        ];
        let mut out = Vec::with_capacity(len + 32);
        let mut x = seed;
        while out.len() < len {
            x = x
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(WORDS[(x >> 33) as usize % WORDS.len()]);
        }
        out.truncate(len);
        out
    }

    #[test]
    fn large_streams_round_trip_through_the_reference_decoders() {
        let input = text(3 << 20, 7);
        for encoding in [Zstd, Gzip] {
            for size in [1, 1000, 16 * 1024, 1 << 20] {
                let source = if size == 1 {
                    &input[..20_000]
                } else {
                    &input[..]
                };
                let mut encoder = Encoder::take(encoding).unwrap();
                let mut wire = Vec::new();
                for piece in source.chunks(size) {
                    wire.extend_from_slice(&encoder.chunk(piece).unwrap());
                }
                wire.extend_from_slice(&encoder.finish().unwrap());
                let mut decoder = Decoder::new(encoding);
                assert_eq!(
                    decoder.feed(&wire),
                    source,
                    "{encoding:?}, chunks of {size}"
                );
                assert!(decoder.ended(), "{encoding:?}, chunks of {size}");
                if size >= 16 * 1024 {
                    assert!(
                        wire.len() * 3 < source.len(),
                        "{encoding:?}, chunks of {size}: {} bytes from {}",
                        wire.len(),
                        source.len()
                    );
                }
            }
        }
    }

    #[test]
    fn zstd_window_fits_the_http_decoder_limit() {
        let input = text(24 << 20, 3);
        let mut encoder = Encoder::take(Zstd).unwrap();
        let mut decoder = Decoder::new(Zstd);
        let mut decoded = 0;
        for piece in input.chunks(256 * 1024) {
            decoded += decoder.feed(&encoder.chunk(piece).unwrap()).len();
        }
        decoded += decoder.feed(&encoder.finish().unwrap()).len();
        assert_eq!(decoded, input.len());
        assert!(decoder.ended());
    }

    #[test]
    fn whole_bodies_are_single_complete_streams() {
        for encoding in [Zstd, Gzip] {
            for input in [&b""[..], b"x", &text(100_000, 1)] {
                let encoded = Encoder::take(encoding).unwrap().whole(input).unwrap();
                let mut decoder = Decoder::new(encoding);
                assert_eq!(
                    decoder.feed(&encoded),
                    input,
                    "{encoding:?}, {} bytes",
                    input.len()
                );
                assert!(decoder.ended(), "{encoding:?}, {} bytes", input.len());
            }
        }
    }

    #[test]
    fn a_reused_compressor_starts_a_fresh_stream() {
        for encoding in [Zstd, Gzip] {
            let mut abandoned = Encoder::take(encoding).unwrap();
            abandoned.chunk(&text(50_000, 9)).unwrap();
            drop(abandoned);
            let finished = Encoder::take(encoding)
                .unwrap()
                .whole(&text(5000, 4))
                .unwrap();
            assert!(!finished.is_empty());
            for round in 0..3 {
                let mut encoder = Encoder::take(encoding).unwrap();
                let mut decoder = Decoder::new(encoding);
                for i in 0..5 {
                    let chunk = encoder.chunk(&event(i)).unwrap();
                    assert_eq!(
                        decoder.feed(&chunk),
                        event(i),
                        "{encoding:?}, round {round}"
                    );
                }
                decoder.feed(&encoder.finish().unwrap());
                assert!(decoder.ended(), "{encoding:?}, round {round}");
            }
        }
    }
}
