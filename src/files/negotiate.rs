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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Conditional {
    NotModified,
    Proceed,
}

/// If-None-Match (weak comparison, `*`), then If-Modified-Since when no If-None-Match. An
/// If-Modified-Since is only evaluated for a file that has a Last-Modified (`mtime > 1`), and
/// only in IMF-fixdate form; anything else proceeds, which is always a correct answer.
pub(crate) fn conditional(
    if_none_match: Option<&[u8]>,
    if_modified_since: Option<&[u8]>,
    etag: Option<&[u8]>,
    mtime: i64,
) -> Conditional {
    let not_modified = match (if_none_match, if_modified_since) {
        (Some(list), _) => {
            list.trim_ascii() == b"*"
                || etag
                    .and_then(entity_tag)
                    .is_some_and(|(_, ours)| entity_tags(list).any(|(_, tag)| tag == ours))
        }
        (None, Some(date)) => {
            mtime > 1 && parse_http_date(date.trim_ascii()).is_some_and(|since| mtime <= since)
        }
        (None, None) => false,
    };
    if not_modified {
        Conditional::NotModified
    } else {
        Conditional::Proceed
    }
}

/// Splits an entity-tag (`"x"` or `W/"x"`) into (weak, opaque tag with its quotes). `None`
/// when `v` is not exactly one entity-tag.
pub(crate) fn entity_tag(v: &[u8]) -> Option<(bool, &[u8])> {
    let mut tags = EntityTags { rest: v };
    let tag = tags.next()?;
    tags.rest.trim_ascii().is_empty().then_some(tag)
}

/// The entity-tags of an If-None-Match or If-Range list. Stops at the first malformed
/// element, so garbage never matches.
fn entity_tags(list: &[u8]) -> EntityTags<'_> {
    EntityTags { rest: list }
}

struct EntityTags<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for EntityTags<'a> {
    type Item = (bool, &'a [u8]);

    fn next(&mut self) -> Option<(bool, &'a [u8])> {
        let start = self
            .rest
            .iter()
            .position(|&b| !matches!(b, b' ' | b'\t' | b','))?;
        let mut v = &self.rest[start..];
        let weak = v.starts_with(b"W/");
        if weak {
            v = &v[2..];
        }
        let close = match v {
            [b'"', tail @ ..] => tail.iter().position(|&b| b == b'"')? + 1,
            _ => {
                self.rest = &[];
                return None;
            }
        };
        let tag = &v[..=close];
        if !tag[1..close]
            .iter()
            .all(|&b| b == 0x21 || (0x23..=0x7e).contains(&b) || b >= 0x80)
        {
            self.rest = &[];
            return None;
        }
        self.rest = &v[close + 1..];
        Some((weak, tag))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RangeDecision {
    Full,
    Partial(Range<u64>),
    NotSatisfiable,
}

/// One `bytes=a-b` / `a-` / `-n` range; anything else (multi-range, other units, bad syntax)
/// is `Full`. `If-Range` must match the strong ETag, else `Full`; its date form is `Full`.
pub(crate) fn range(
    range: Option<&[u8]>,
    if_range: Option<&[u8]>,
    etag: Option<&[u8]>,
    len: u64,
) -> RangeDecision {
    let Some(range) = range else {
        return RangeDecision::Full;
    };
    if let Some(if_range) = if_range {
        let strong_match = match (entity_tag(if_range.trim_ascii()), etag.and_then(entity_tag)) {
            (Some((false, theirs)), Some((false, ours))) => theirs == ours,
            _ => false,
        };
        if !strong_match {
            return RangeDecision::Full;
        }
    }
    let range = range.trim_ascii();
    let Some(spec) = range
        .get(..6)
        .filter(|unit| unit.eq_ignore_ascii_case(b"bytes="))
        .map(|_| &range[6..])
    else {
        return RangeDecision::Full;
    };
    let mut specs = spec
        .split(|&b| b == b',')
        .map(<[u8]>::trim_ascii)
        .filter(|s| !s.is_empty());
    let (Some(spec), None) = (specs.next(), specs.next()) else {
        return RangeDecision::Full;
    };
    let Some(dash) = spec.iter().position(|&b| b == b'-') else {
        return RangeDecision::Full;
    };
    let (first, last) = (&spec[..dash], &spec[dash + 1..]);
    match (first, last) {
        ([], []) => RangeDecision::Full,
        ([], suffix) => match parse_digits(suffix) {
            Some(Digits::Value(0)) => RangeDecision::NotSatisfiable,
            Some(_) if len == 0 => RangeDecision::NotSatisfiable,
            Some(Digits::Value(n)) => RangeDecision::Partial(len.saturating_sub(n)..len),
            Some(Digits::Overflow) => RangeDecision::Partial(0..len),
            None => RangeDecision::Full,
        },
        (first, last) => {
            let Some(first) = parse_digits(first) else {
                return RangeDecision::Full;
            };
            let last = match last {
                [] => Digits::Overflow,
                last => match parse_digits(last) {
                    Some(last) => last,
                    None => return RangeDecision::Full,
                },
            };
            match (first, last) {
                (Digits::Value(a), Digits::Value(b)) if b < a => RangeDecision::Full,
                (Digits::Overflow, Digits::Value(_)) => RangeDecision::Full,
                (Digits::Value(a), _) if a < len => {
                    let end = match last {
                        Digits::Value(b) => b.saturating_add(1).min(len),
                        Digits::Overflow => len,
                    };
                    RangeDecision::Partial(a..end)
                }
                _ => RangeDecision::NotSatisfiable,
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Digits {
    Value(u64),
    /// More than `u64::MAX`: as a first byte position never satisfiable, as a last position or
    /// a suffix length the whole representation.
    Overflow,
}

fn parse_digits(v: &[u8]) -> Option<Digits> {
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let value = v.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    });
    Some(value.map_or(Digits::Overflow, Digits::Value))
}

/// Content type by extension, from a static table (Go's builtin table plus the web types the
/// static sites serve: .md, .mdx, .webmanifest, .avif, .woff2, ...), `; charset=utf-8` on text
/// types. Unknown: `application/octet-stream`.
pub(crate) fn content_type(path: &[u8]) -> &'static str {
    const UNKNOWN: &str = "application/octet-stream";
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(path);
    let Some(dot) = name.iter().rposition(|&b| b == b'.') else {
        return UNKNOWN;
    };
    let ext = &name[dot + 1..];
    let mut lower = [0u8; 12];
    let Some(ext) = lower.get_mut(..ext.len()).map(|buf| {
        buf.copy_from_slice(ext);
        buf.make_ascii_lowercase();
        &*buf
    }) else {
        return UNKNOWN;
    };
    match ext {
        b"html" | b"htm" => "text/html; charset=utf-8",
        b"css" => "text/css; charset=utf-8",
        b"js" | b"mjs" | b"cjs" => "text/javascript; charset=utf-8",
        b"txt" => "text/plain; charset=utf-8",
        b"md" | b"mdx" | b"markdown" => "text/markdown; charset=utf-8",
        b"xml" => "text/xml; charset=utf-8",
        b"csv" => "text/csv; charset=utf-8",
        b"json" | b"map" => "application/json",
        b"jsonld" => "application/ld+json",
        b"webmanifest" => "application/manifest+json",
        b"rss" => "application/rss+xml",
        b"atom" => "application/atom+xml",
        b"wasm" => "application/wasm",
        b"pdf" => "application/pdf",
        b"zip" => "application/zip",
        b"gz" => "application/gzip",
        b"zst" => "application/zstd",
        b"xz" => "application/x-xz",
        b"tar" => "application/x-tar",
        b"svg" => "image/svg+xml",
        b"png" => "image/png",
        b"jpg" | b"jpeg" => "image/jpeg",
        b"gif" => "image/gif",
        b"webp" => "image/webp",
        b"avif" => "image/avif",
        b"ico" => "image/x-icon",
        b"woff" => "font/woff",
        b"woff2" => "font/woff2",
        b"ttf" => "font/ttf",
        b"otf" => "font/otf",
        b"mp4" => "video/mp4",
        b"webm" => "video/webm",
        b"mp3" => "audio/mpeg",
        b"ogg" | b"opus" => "audio/ogg",
        b"wav" => "audio/wav",
        b"flac" => "audio/flac",
        _ => UNKNOWN,
    }
}

const DAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) of a unix time in years 0000..=9999.
pub(crate) fn http_date(unix: i64) -> [u8; 29] {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
    out[..3].copy_from_slice(DAYS[days.rem_euclid(7) as usize]);
    put2(&mut out[5..7], day);
    out[8..11].copy_from_slice(MONTHS[month as usize - 1]);
    put2(&mut out[12..14], year / 100);
    put2(&mut out[14..16], year % 100);
    put2(&mut out[17..19], secs / 3600);
    put2(&mut out[20..22], secs / 60 % 60);
    put2(&mut out[23..25], secs % 60);
    out
}

fn put2(out: &mut [u8], n: i64) {
    out[0] = b'0' + (n / 10 % 10) as u8;
    out[1] = b'0' + (n % 10) as u8;
}

/// Unix time of an IMF-fixdate; `None` for any other form (the obsolete RFC 850 and asctime
/// forms included).
pub(crate) fn parse_http_date(v: &[u8]) -> Option<i64> {
    let v: &[u8; 29] = v.try_into().ok()?;
    if &v[3..5] != b", " || v[7] != b' ' || v[11] != b' ' || v[16] != b' ' || &v[25..] != b" GMT" {
        return None;
    }
    if v[19] != b':' || v[22] != b':' {
        return None;
    }
    let num = |s: &[u8]| -> Option<i64> {
        s.iter().try_fold(0i64, |n, &d| {
            d.is_ascii_digit().then(|| n * 10 + i64::from(d - b'0'))
        })
    };
    let day = num(&v[5..7])?;
    let month = MONTHS.iter().position(|m| m[..] == v[8..11])? as i64 + 1;
    let year = num(&v[12..16])?;
    let (hour, minute, second) = (num(&v[17..19])?, num(&v[20..22])?, num(&v[23..25])?);
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Howard Hinnant's `days_from_civil`: days since 1970-01-01 of a proleptic Gregorian date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
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

    fn cond(inm: Option<&str>, ims: Option<&str>, etag: &str, mtime: i64) -> Conditional {
        conditional(
            inm.map(str::as_bytes),
            ims.map(str::as_bytes),
            Some(etag.as_bytes()),
            mtime,
        )
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        use Conditional::*;
        assert_eq!(cond(Some(r#""a""#), None, r#""a""#, 1), NotModified);
        assert_eq!(cond(Some(r#"W/"a""#), None, r#""a""#, 1), NotModified);
        assert_eq!(cond(Some(r#""a""#), None, r#"W/"a""#, 1), NotModified);
        assert_eq!(cond(Some(r#""b", "a""#), None, r#""a""#, 1), NotModified);
        assert_eq!(cond(Some(r#""b""#), None, r#""a""#, 1), Proceed);
        assert_eq!(cond(Some("*"), None, r#""a""#, 1), NotModified);
        assert_eq!(cond(Some(r#""a,b""#), None, r#""a,b""#, 1), NotModified);
        assert_eq!(cond(Some(r#""a""#), None, r#""a,b""#, 1), Proceed);
        assert_eq!(
            cond(Some("a"), None, "a", 1),
            Proceed,
            "an unquoted tag is not an entity-tag"
        );
        assert_eq!(cond(Some(r#""a"#), None, r#""a""#, 1), Proceed);
    }

    #[test]
    fn if_modified_since_only_without_if_none_match() {
        use Conditional::*;
        let date = "Sun, 06 Nov 1994 08:49:37 GMT";
        assert_eq!(cond(None, Some(date), r#""a""#, 784111777), NotModified);
        assert_eq!(cond(None, Some(date), r#""a""#, 784111700), NotModified);
        assert_eq!(cond(None, Some(date), r#""a""#, 784111778), Proceed);
        assert_eq!(
            cond(Some(r#""b""#), Some(date), r#""a""#, 784111700),
            Proceed,
            "If-None-Match present: If-Modified-Since is ignored"
        );
        assert_eq!(
            cond(None, Some(date), r#""a""#, 1),
            Proceed,
            "store files have no Last-Modified to compare"
        );
        assert_eq!(
            cond(None, Some("Sunday, 06-Nov-94 08:49:37 GMT"), r#""a""#, 7),
            Proceed
        );
        assert_eq!(cond(None, None, r#""a""#, 7), Proceed);
    }

    fn ranged(header: &str, len: u64) -> RangeDecision {
        range(Some(header.as_bytes()), None, Some(br#""e""#), len)
    }

    #[test]
    fn single_byte_ranges() {
        use RangeDecision::*;
        assert_eq!(ranged("bytes=0-499", 10000), Partial(0..500));
        assert_eq!(ranged("bytes=500-999", 10000), Partial(500..1000));
        assert_eq!(ranged("bytes=-500", 10000), Partial(9500..10000));
        assert_eq!(ranged("bytes=9500-", 10000), Partial(9500..10000));
        assert_eq!(ranged("bytes=0-0", 10000), Partial(0..1));
        assert_eq!(ranged("bytes=-1", 10000), Partial(9999..10000));
        assert_eq!(ranged("bytes=0-99999", 10000), Partial(0..10000));
        assert_eq!(ranged("bytes=-20000", 10000), Partial(0..10000));
        assert_eq!(ranged("BYTES=0-1", 10000), Partial(0..2));
        assert_eq!(ranged("bytes= 0-1 ,", 10000), Partial(0..2));
        assert_eq!(
            ranged("bytes=0-99999999999999999999999", 10),
            Partial(0..10)
        );
    }

    #[test]
    fn unsatisfiable_ranges() {
        use RangeDecision::*;
        assert_eq!(ranged("bytes=10000-", 10000), NotSatisfiable);
        assert_eq!(ranged("bytes=10000-10001", 10000), NotSatisfiable);
        assert_eq!(ranged("bytes=-0", 10000), NotSatisfiable);
        assert_eq!(ranged("bytes=0-", 0), NotSatisfiable);
        assert_eq!(ranged("bytes=-5", 0), NotSatisfiable);
        assert_eq!(ranged("bytes=99999999999999999999999-", 10), NotSatisfiable);
    }

    #[test]
    fn ignored_ranges_serve_the_full_representation() {
        use RangeDecision::*;
        assert_eq!(ranged("bytes=0-0,-1", 10000), Full, "multi-range");
        assert_eq!(ranged("bytes=500-499", 10000), Full, "last before first");
        assert_eq!(ranged("items=0-1", 10000), Full, "other unit");
        assert_eq!(ranged("bytes=a-b", 10000), Full);
        assert_eq!(ranged("bytes=-", 10000), Full);
        assert_eq!(ranged("bytes=5", 10000), Full);
        assert_eq!(ranged("bytes=+1-2", 10000), Full);
        assert_eq!(range(None, None, Some(br#""e""#), 10), Full);
    }

    #[test]
    fn if_range_needs_the_strong_etag() {
        use RangeDecision::*;
        let r = |if_range: &str, etag: &str| {
            range(
                Some(b"bytes=0-1"),
                Some(if_range.as_bytes()),
                Some(etag.as_bytes()),
                10,
            )
        };
        assert_eq!(r(r#""e""#, r#""e""#), Partial(0..2));
        assert_eq!(r(r#""f""#, r#""e""#), Full);
        assert_eq!(r(r#"W/"e""#, r#""e""#), Full);
        assert_eq!(r(r#""e""#, r#"W/"e""#), Full);
        assert_eq!(r("Sun, 06 Nov 1994 08:49:37 GMT", r#""e""#), Full);
    }

    #[test]
    fn http_dates() {
        let s = |unix| String::from_utf8(http_date(unix).to_vec()).unwrap();
        assert_eq!(s(784111777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(s(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(s(951782400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(s(253402300799), "Fri, 31 Dec 9999 23:59:59 GMT");
        assert_eq!(
            parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        assert_eq!(
            parse_http_date(b"Tue, 29 Feb 2000 00:00:00 GMT"),
            Some(951782400)
        );
        assert_eq!(parse_http_date(b"Sun, 06 Nov 1994 08:49:37 UTC"), None);
        assert_eq!(parse_http_date(b"Sun, 06 Nov 1994 24:49:37 GMT"), None);
        assert_eq!(parse_http_date(b"Sun, 06 Xyz 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date(b"Sun Nov  6 08:49:37 1994"), None);
    }

    #[test]
    fn content_types_by_extension() {
        for (path, want) in [
            ("/index.html", "text/html; charset=utf-8"),
            (
                "/_app/immutable/entry/app.ABC.JS",
                "text/javascript; charset=utf-8",
            ),
            ("/_astro/index.Bx1.css", "text/css; charset=utf-8"),
            ("/_md/blog.md", "text/markdown; charset=utf-8"),
            ("/robots.txt", "text/plain; charset=utf-8"),
            ("/manifest.webmanifest", "application/manifest+json"),
            ("/fonts/inter.woff2", "font/woff2"),
            ("/og/post.avif", "image/avif"),
            ("/favicon.ico", "image/x-icon"),
            ("/sitemap.xml", "text/xml; charset=utf-8"),
            ("/app.wasm", "application/wasm"),
            ("/README", "application/octet-stream"),
            ("/dir.d/README", "application/octet-stream"),
            ("/x.averyveryverylongextension", "application/octet-stream"),
            ("/x.unknown", "application/octet-stream"),
        ] {
            assert_eq!(content_type(path.as_bytes()), want, "{path}");
        }
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
