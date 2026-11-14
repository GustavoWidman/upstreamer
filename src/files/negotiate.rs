//! Pure HTTP semantics for representations: content coding choice, conditionals, ranges,
//! content types. No IO; unit-tested against tables.

use crate::encode::Encoding;
use std::ops::Range;

/// Picks a coding: the client's Accept-Encoding q-values decide among `offered` (config
/// order breaks ties), restricted to those `available`. A coding the header does not name
/// takes the q of `*`, if any. `None` (identity) when the header is absent or accepts none of
/// them; `identity;q=0` still serves identity (refusing would only break clients). Used by
/// precompressed sidecars and by dynamic compression alike.
pub(crate) fn pick_encoding(
    accept: Option<&[u8]>,
    offered: &[Encoding],
    available: impl Fn(Encoding) -> bool,
) -> Option<Encoding> {
    let accept = accept?;
    let mut best: Option<(u16, Encoding)> = None;
    for &encoding in offered {
        let q = accepted_q(accept, encoding.token());
        if q > 0 && best.is_none_or(|(b, _)| q > b) && available(encoding) {
            best = Some((q, encoding));
        }
    }
    best.map(|(_, encoding)| encoding)
}

/// The q-value (in thousandths) the header gives `token`, falling back to `*`; 0 if neither.
fn accepted_q(header: &[u8], token: &[u8]) -> u16 {
    let mut wildcard = None;
    for item in header.split(|&b| b == b',') {
        let mut parts = item.split(|&b| b == b';');
        let coding = trim(parts.next().unwrap_or_default());
        let q = parts
            .filter_map(|p| {
                let p = trim(p);
                (p.len() >= 2 && p[..2].eq_ignore_ascii_case(b"q=")).then(|| parse_q(&p[2..]))
            })
            .next()
            .unwrap_or(Some(1000));
        let Some(q) = q else { continue };
        if coding.eq_ignore_ascii_case(token)
            || (token == b"gzip" && coding.eq_ignore_ascii_case(b"x-gzip"))
        {
            return q;
        }
        if coding == b"*" {
            wildcard = Some(q);
        }
    }
    wildcard.unwrap_or(0)
}

/// RFC 9110 qvalue: `0`, `1`, `0.xxx`, `1.000`. `None` for anything else.
fn parse_q(v: &[u8]) -> Option<u16> {
    match v {
        [b'0'] | [b'0', b'.'] => Some(0),
        [b'1'] | [b'1', b'.'] => Some(1000),
        [b'1', b'.', rest @ ..] if rest.len() <= 3 && rest.iter().all(|&b| b == b'0') => Some(1000),
        [b'0', b'.', rest @ ..] if rest.len() <= 3 && rest.iter().all(u8::is_ascii_digit) => {
            let mut n = 0u16;
            for i in 0..3 {
                n = n * 10 + rest.get(i).map_or(0, |d| (d - b'0') as u16);
            }
            Some(n)
        }
        _ => None,
    }
}

fn trim(v: &[u8]) -> &[u8] {
    v.trim_ascii()
}

pub(crate) enum Conditional {
    NotModified,
    Proceed,
}

/// If-None-Match (weak comparison, `*`), then If-Modified-Since when no If-None-Match.
pub(crate) fn conditional(
    if_none_match: Option<&[u8]>,
    if_modified_since: Option<&[u8]>,
    etag: Option<&[u8]>,
    mtime: i64,
) -> Conditional {
    todo!()
}

pub(crate) enum RangeDecision {
    Full,
    Partial(Range<u64>),
    NotSatisfiable,
}

/// One `bytes=a-b` / `a-` / `-n` range; anything else (multi-range, other units) is `Full`.
/// `If-Range` must match the strong ETag, else `Full`.
pub(crate) fn range(
    range: Option<&[u8]>,
    if_range: Option<&[u8]>,
    etag: Option<&[u8]>,
    len: u64,
) -> RangeDecision {
    todo!()
}

/// Content type by extension, from a static table (Go's builtin table plus the web types the
/// static sites serve: .md, .mdx, .webmanifest, .avif, .woff2, ...), `; charset=utf-8` on text
/// types. Unknown: `application/octet-stream`.
pub(crate) fn content_type(path: &[u8]) -> &'static str {
    todo!()
}

/// Whether a content type is worth compressing (text/*, json, javascript, xml, svg, wasm,
/// fonts that are not already compressed). `text/event-stream` is never compressed. Matched
/// on the media type without parameters, ASCII case-insensitively.
pub(crate) fn compressible(content_type: &[u8]) -> bool {
    let media = trim(
        content_type
            .split(|&b| b == b';')
            .next()
            .unwrap_or_default(),
    );
    let mut lower = [0u8; 64];
    let Some(media) = lower.get_mut(..media.len()).map(|buf| {
        buf.copy_from_slice(media);
        buf.make_ascii_lowercase();
        &*buf
    }) else {
        return false;
    };
    if media == b"text/event-stream" {
        return false;
    }
    let (kind, subtype) = match media.iter().position(|&b| b == b'/') {
        Some(i) => (&media[..i], &media[i + 1..]),
        None => return false,
    };
    match kind {
        b"text" => true,
        b"application" => {
            matches!(
                subtype,
                b"json"
                    | b"javascript"
                    | b"x-javascript"
                    | b"ecmascript"
                    | b"xml"
                    | b"wasm"
                    | b"x-ndjson"
                    | b"vnd.ms-fontobject"
            ) || subtype.ends_with(b"+json")
                || subtype.ends_with(b"+xml")
        }
        b"image" => matches!(
            subtype,
            b"svg+xml" | b"x-icon" | b"vnd.microsoft.icon" | b"bmp"
        ),
        b"font" => matches!(subtype, b"ttf" | b"otf" | b"collection"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Encoding::*;

    fn pick(accept: Option<&str>, offered: &[Encoding]) -> Option<Encoding> {
        pick_encoding(accept.map(str::as_bytes), offered, |_| true)
    }

    #[test]
    fn encoding_by_q_then_config_order() {
        assert_eq!(pick(Some("gzip, br"), &[Br, Zstd, Gzip]), Some(Br));
        assert_eq!(pick(Some("gzip, br;q=0.5"), &[Br, Zstd, Gzip]), Some(Gzip));
        assert_eq!(
            pick(Some("zstd, gzip"), &[Gzip, Zstd]),
            Some(Gzip),
            "ties follow the config"
        );
        assert_eq!(pick(Some("br;q=0, gzip;q=0.001"), &[Br, Gzip]), Some(Gzip));
        assert_eq!(pick(Some("*"), &[Zstd, Gzip]), Some(Zstd));
        assert_eq!(pick(Some("*;q=0.2, gzip;q=0.1"), &[Zstd, Gzip]), Some(Zstd));
        assert_eq!(pick(Some("x-gzip"), &[Gzip]), Some(Gzip));
        assert_eq!(pick(Some("GZIP;Q=1.0"), &[Gzip]), Some(Gzip));
    }

    #[test]
    fn identity_when_nothing_acceptable() {
        assert_eq!(pick(None, &[Br, Gzip]), None);
        assert_eq!(pick(Some(""), &[Br, Gzip]), None);
        assert_eq!(pick(Some("identity"), &[Br, Gzip]), None);
        assert_eq!(pick(Some("br;q=0"), &[Br]), None);
        assert_eq!(pick(Some("identity;q=0"), &[Br]), None);
        assert_eq!(
            pick(Some("br;q=2"), &[Br]),
            None,
            "an invalid qvalue is ignored"
        );
        assert_eq!(pick(Some("gzip"), &[]), None);
    }

    #[test]
    fn only_available_encodings() {
        assert_eq!(
            pick_encoding(Some(b"br, gzip"), &[Br, Gzip], |e| e == Gzip),
            Some(Gzip)
        );
    }

    #[test]
    fn compressible_types() {
        for t in [
            "text/html; charset=utf-8",
            "Text/CSS",
            "application/json",
            "application/rss+xml",
            "application/manifest+json",
            "image/svg+xml",
            "application/wasm",
            "font/ttf",
        ] {
            assert!(compressible(t.as_bytes()), "{t}");
        }
        for t in [
            "text/event-stream",
            "image/png",
            "font/woff2",
            "application/octet-stream",
            "application/zip",
            "",
            "text",
        ] {
            assert!(!compressible(t.as_bytes()), "{t}");
        }
    }
}
