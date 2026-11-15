//! The two facts renewal reads from an issued certificate (RFC 5280 section 4.1): its validity
//! period and the DNS names of its subjectAltName. A DER walk of only those fields; the
//! certificate's signature and key are checked where it is loaded, not here.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// What renewal needs to know about a certificate on disk.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Leaf {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// subjectAltName dNSName entries, lowercased, in certificate order.
    pub names: Vec<Box<str>>,
}

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const OID: u8 = 0x06;
const BOOLEAN: u8 = 0x01;
const OCTET_STRING: u8 = 0x04;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const VERSION: u8 = 0xa0;
const EXTENSIONS: u8 = 0xa3;
const DNS_NAME: u8 = 0x82;
/// 2.5.29.17
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// The validity and DNS names of a DER certificate; `None` when it does not parse.
pub(super) fn leaf(der: &[u8]) -> Option<Leaf> {
    let mut input = der;
    let mut cert = expect(&mut input, SEQUENCE)?;
    let mut tbs = expect(&mut cert, SEQUENCE)?;
    if tbs.first() == Some(&VERSION) {
        next(&mut tbs)?;
    }
    expect(&mut tbs, INTEGER)?;
    expect(&mut tbs, SEQUENCE)?; // signature algorithm
    expect(&mut tbs, SEQUENCE)?; // issuer
    let mut validity = expect(&mut tbs, SEQUENCE)?;
    let not_before = time(&mut validity)?;
    let not_after = time(&mut validity)?;
    expect(&mut tbs, SEQUENCE)?; // subject
    expect(&mut tbs, SEQUENCE)?; // subjectPublicKeyInfo
    let mut names = Vec::new();
    while let Some((tag, body)) = next(&mut tbs) {
        if tag != EXTENSIONS {
            continue;
        }
        let mut body = body;
        let mut list = expect(&mut body, SEQUENCE)?;
        while !list.is_empty() {
            let mut extension = expect(&mut list, SEQUENCE)?;
            let id = expect(&mut extension, OID)?;
            if extension.first() == Some(&BOOLEAN) {
                next(&mut extension)?;
            }
            let mut value = expect(&mut extension, OCTET_STRING)?;
            if id != SUBJECT_ALT_NAME {
                continue;
            }
            let mut general_names = expect(&mut value, SEQUENCE)?;
            while let Some((tag, name)) = next(&mut general_names) {
                if tag == DNS_NAME {
                    let name = std::str::from_utf8(name).ok()?;
                    names.push(name.to_ascii_lowercase().into());
                }
            }
        }
    }
    Some(Leaf {
        not_before,
        not_after,
        names,
    })
}

/// The next element's tag and contents. Definite lengths only, as DER requires.
fn next<'a>(input: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (bytes, after) = rest.split_at(count);
        rest = after;
        bytes.iter().fold(0, |n, &b| n << 8 | usize::from(b))
    };
    if rest.len() < len {
        return None;
    }
    let (body, after) = rest.split_at(len);
    *input = after;
    Some((tag, body))
}

fn expect<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    match next(input)? {
        (t, body) if t == tag => Some(body),
        _ => None,
    }
}

/// UTCTime (`YYMMDDHHMMSSZ`, years 1950 to 2049) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
fn time(input: &mut &[u8]) -> Option<SystemTime> {
    let (tag, body) = next(input)?;
    let text = std::str::from_utf8(body).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        UTC_TIME if text.len() == 12 => {
            let yy: i64 = text[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        GENERALIZED_TIME if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |i: usize| rest[i..i + 2].parse::<i64>().ok();
    let (month, day) = (field(0)?, field(2)?);
    let (hour, minute, second) = (field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).ok()?))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn reads_the_validity_and_dns_names_of_a_certificate() {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![
            "A.example.com".to_owned(),
            "b.example.com".to_owned(),
        ])
        .unwrap();
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress([192, 0, 2, 1].into()));
        params.not_before = rcgen::date_time_ymd(2025, 3, 1);
        // GeneralizedTime from 2050 on (RFC 5280 section 4.1.2.5).
        params.not_after = rcgen::date_time_ymd(2051, 2, 28);
        let cert = params.self_signed(&key).unwrap();
        let leaf = leaf(cert.der()).expect("a certificate parses");
        assert_eq!(leaf.not_before, at(1_740_787_200), "2025-03-01T00:00:00Z");
        assert_eq!(leaf.not_after, at(2_561_155_200), "2051-02-28T00:00:00Z");
        assert_eq!(
            leaf.names,
            ["a.example.com".into(), "b.example.com".into()] as [Box<str>; 2]
        );
    }

    #[test]
    fn rejects_what_is_not_a_certificate() {
        assert_eq!(leaf(b""), None);
        assert_eq!(
            leaf(&[0x30, 0x82, 0xff, 0xff, 0x30]),
            None,
            "a length past the end"
        );
        assert_eq!(
            leaf(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            None,
            "no tbsCertificate"
        );
    }

    #[test]
    fn utc_time_years_wrap_at_1950() {
        let mut utc: &[u8] = b"\x17\x0d491231235959Z";
        assert_eq!(
            time(&mut utc),
            Some(at(2_524_607_999)),
            "2049-12-31T23:59:59Z"
        );
        let mut utc: &[u8] = b"\x17\x0d700101000000Z";
        assert_eq!(time(&mut utc), Some(at(0)), "1970-01-01T00:00:00Z");
        let mut utc: &[u8] = b"\x17\x0d500101000000Z";
        assert_eq!(time(&mut utc), None, "1950 is before the Unix epoch");
    }
}
