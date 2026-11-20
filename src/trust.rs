//! Trusted proxies: the client address a trusted peer (a CDN, a load balancer) forwards.
//!
//! When the plan has `trustedProxies` and the connection's peer is one of them, the
//! exchange's client address becomes the address the configured header names, before the
//! access log, routing, rate-limit and hash keys read it. `{peer_host}` still names the peer.
//! An untrusted peer's header is ignored. A plan without `trustedProxies` has no `trust`, and
//! the pipeline never calls in here.
//!
//! The trusted set is a sorted list of disjoint address ranges per family, so a lookup is a
//! binary search over a few `u32`s (or `u128`s) however the ranges were written. Nothing here
//! allocates per request.

mod cloudflare;

use crate::exchange::{ConnInfo, Exchange};
use crate::msg::{HeaderName, Known, RequestHead};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whose header is believed, and which header. Built by `plan::compile::trust`.
#[derive(Debug)]
pub(crate) struct TrustPlan {
    peers: Nets,
    header: Header,
}

impl TrustPlan {
    pub(crate) fn new(peers: Nets, header: Header) -> TrustPlan {
        TrustPlan { peers, header }
    }
}

/// The request header that carries the client address.
#[derive(Debug)]
pub(crate) enum Header {
    /// `CF-Connecting-IP` or `X-Real-IP`: one field, one address.
    Single(HeaderName),
    /// `X-Forwarded-For`: a list, read from the right.
    ForwardedFor,
}

impl Header {
    /// The header a config names, in any letter case; `None` for any other name.
    pub(crate) fn parse(name: &str) -> Option<Header> {
        if name.eq_ignore_ascii_case("X-Forwarded-For") {
            Some(Header::ForwardedFor)
        } else if name.eq_ignore_ascii_case("CF-Connecting-IP")
            || name.eq_ignore_ascii_case("X-Real-IP")
        {
            HeaderName::new(name).map(Header::Single)
        } else {
            None
        }
    }
}

/// A network: an address and a prefix length, with no bits set past the prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cidr {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

impl Cidr {
    /// Parses `10.0.0.0/8`, `2001:db8::/32` or a bare address (a single host). An IPv6
    /// network inside `::ffff:0:0/96` becomes the IPv4 network it maps, because lookups
    /// canonicalise addresses the same way.
    pub(crate) fn parse(text: &str) -> Result<Cidr, String> {
        let (addr, len) = match text.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("`{text}` is not an IP address or a CIDR range"))?;
        let bits: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => bits,
            Some(len) => Some(len)
                .filter(|len| len.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|len| len.parse::<u8>().ok())
                .filter(|&len| len <= bits)
                .ok_or_else(|| format!("`{text}`: the prefix length must be 0 to {bits}"))?,
        };
        let cidr = match addr {
            IpAddr::V4(a) => Cidr::V4(a, len),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) if len >= 96 => Cidr::V4(v4, len - 96),
                _ => Cidr::V6(a, len),
            },
        };
        if let Some(network) = cidr.network()
            && network != cidr
        {
            return Err(format!(
                "`{text}` has bits set past its prefix; write `{network}`"
            ));
        }
        Ok(cidr)
    }

    /// The same range with the host bits cleared, or `None` when they already are.
    fn network(self) -> Option<Cidr> {
        match self {
            Cidr::V4(a, len) => {
                let net = Ipv4Addr::from(u32::from(a) & mask4(len));
                (net != a).then_some(Cidr::V4(net, len))
            }
            Cidr::V6(a, len) => {
                let net = Ipv6Addr::from(u128::from(a) & mask6(len));
                (net != a).then_some(Cidr::V6(net, len))
            }
        }
    }

    /// Whether the range holds every address of its family.
    pub(crate) fn is_everything(self) -> bool {
        matches!(self, Cidr::V4(_, 0) | Cidr::V6(_, 0))
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cidr::V4(a, len) => write!(f, "{a}/{len}"),
            Cidr::V6(a, len) => write!(f, "{a}/{len}"),
        }
    }
}

fn mask4(len: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
}

fn mask6(len: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)
}

/// Cloudflare's published ranges, for the `cloudflare` preset.
pub(crate) fn cloudflare() -> impl Iterator<Item = Cidr> {
    cloudflare::IPV4
        .iter()
        .chain(cloudflare::IPV6)
        .filter_map(|range| Cidr::parse(range).ok())
}

/// A set of networks, searched by binary search.
#[derive(Debug, Default)]
pub(crate) struct Nets {
    v4: Box<[(u32, u32)]>,
    v6: Box<[(u128, u128)]>,
}

impl Nets {
    pub(crate) fn new(cidrs: impl IntoIterator<Item = Cidr>) -> Nets {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for cidr in cidrs {
            match cidr {
                Cidr::V4(a, len) => {
                    let lo = u32::from(a) & mask4(len);
                    v4.push((lo, lo | !mask4(len)));
                }
                Cidr::V6(a, len) => {
                    let lo = u128::from(a) & mask6(len);
                    v6.push((lo, lo | !mask6(len)));
                }
            }
        }
        Nets {
            v4: merge(v4).into(),
            v6: merge(v6).into(),
        }
    }

    /// Whether `ip` is in the set. An IPv4-mapped IPv6 address is looked up as the IPv4
    /// address it maps.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => within(&self.v4, u32::from(a)),
            IpAddr::V6(a) => within(&self.v6, u128::from(a)),
        }
    }
}

/// Sorts ranges and joins the ones that overlap or touch.
fn merge<T: Ord + Copy + Step>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some((_, last_hi)) if lo <= last_hi.next() => *last_hi = (*last_hi).max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// `self + 1`, saturating, so adjacency checks cannot overflow.
trait Step {
    fn next(self) -> Self;
}

impl Step for u32 {
    fn next(self) -> u32 {
        self.saturating_add(1)
    }
}

impl Step for u128 {
    fn next(self) -> u128 {
        self.saturating_add(1)
    }
}

fn within<T: Ord + Copy>(ranges: &[(T, T)], ip: T) -> bool {
    let after = ranges.partition_point(|&(lo, _)| lo <= ip);
    after > 0 && ranges[after - 1].1 >= ip
}

/// Sets `ex.client` from the forwarded address when the peer is trusted. Called once per
/// request of a plan with `trustedProxies`, before anything reads the client address.
///
/// A request the trusted peer sent without a usable address (the header is absent, repeated
/// where one is expected, or not an IP address) keeps the peer as its client: a value that
/// cannot be read is never replaced by a guess.
pub(crate) fn resolve(plan: &TrustPlan, ex: &mut Exchange) {
    if !plan.peers.contains(ex.conn.remote.ip()) {
        return;
    }
    if let Some(client) = plan.forwarded(&ex.req) {
        ex.client = client;
    }
}

impl TrustPlan {
    fn forwarded(&self, req: &RequestHead) -> Option<IpAddr> {
        match &self.header {
            Header::Single(name) => {
                let mut values = req.fields.values(name);
                let value = values.next()?;
                if values.next().is_some() {
                    return None;
                }
                parse_client(value)
            }
            Header::ForwardedFor => {
                self.rightmost_untrusted(req.fields.values_known(Known::XForwardedFor))
            }
        }
    }

    /// The client of an `X-Forwarded-For` chain: the rightmost address that is not a trusted
    /// proxy, because each trusted hop appended the address it received from, so everything
    /// left of the first untrusted address is only a claim. When every address is a trusted
    /// proxy the chain started inside the trusted network and its leftmost address is the
    /// client. Entries are read left to right; the last untrusted one wins, and a value that
    /// is not an address poisons everything to its left, so a chain whose reliable part
    /// cannot be read yields nothing.
    fn rightmost_untrusted<'a>(&self, lines: impl Iterator<Item = &'a [u8]>) -> Option<IpAddr> {
        enum Seen {
            Nothing,
            Untrusted(IpAddr),
            Malformed,
        }
        let mut seen = Seen::Nothing;
        let mut leftmost = None;
        for line in lines {
            for entry in line.split(|&b| b == b',') {
                let entry = trim(entry);
                if entry.is_empty() {
                    continue;
                }
                match parse_client(entry) {
                    None => seen = Seen::Malformed,
                    Some(ip) => {
                        leftmost.get_or_insert(ip);
                        if !self.peers.contains(ip) {
                            seen = Seen::Untrusted(ip);
                        }
                    }
                }
            }
        }
        match seen {
            Seen::Untrusted(ip) => Some(ip),
            Seen::Nothing => leftmost,
            Seen::Malformed => None,
        }
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// An address as a proxy writes it: `192.0.2.1`, `2001:db8::1`, and the forms that carry a
/// port (`192.0.2.1:443`, `[2001:db8::1]:443`, `[2001:db8::1]`). IPv4-mapped IPv6 addresses
/// become IPv4. Anything else (`unknown`, an obfuscated token, a zone id, a list) is `None`.
fn parse_client(value: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(value).ok()?;
    let ip = if let Some(rest) = text.strip_prefix('[') {
        let (inner, tail) = rest.split_once(']')?;
        if !tail.is_empty() {
            port(tail.strip_prefix(':')?)?;
        }
        IpAddr::V6(inner.parse().ok()?)
    } else if text.bytes().filter(|&b| b == b':').count() == 1 {
        let (host, p) = text.split_once(':')?;
        port(p)?;
        IpAddr::V4(host.parse().ok()?)
    } else {
        text.parse().ok()?
    };
    Some(ip.to_canonical())
}

fn port(text: &str) -> Option<()> {
    if text.bytes().all(|b| b.is_ascii_digit()) {
        text.parse::<u16>().ok().map(drop)
    } else {
        None
    }
}

/// The `X-Forwarded-For` a plan with trusted proxies sends upstream, in place of
/// `{remote_host}`: when the client address came from the header of a trusted peer, the chain
/// that peer sent, then the peer; the peer alone otherwise, so an untrusted peer cannot plant
/// addresses of its own.
pub(crate) fn forwarded_for(req: &RequestHead, conn: &ConnInfo, client: IpAddr, out: &mut Vec<u8>) {
    let peer = conn.remote.ip().to_canonical();
    if client.to_canonical() != peer {
        for line in req.fields.values_known(Known::XForwardedFor) {
            if !trim(line).is_empty() {
                out.extend_from_slice(line);
                out.extend_from_slice(b", ");
            }
        }
    }
    let _ = write!(out, "{peer}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{Proto, Scheme};
    use crate::msg::Version;
    use crate::plan::template::{Part, Placeholder, Template};
    use crate::plan::{ListenerKey, ListenerKind};

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn nets(ranges: &[&str]) -> Nets {
        Nets::new(ranges.iter().map(|r| Cidr::parse(r).unwrap()))
    }

    fn plan(header: &str, trusted: &[&str]) -> TrustPlan {
        TrustPlan::new(nets(trusted), Header::parse(header).unwrap())
    }

    fn exchange(peer: &str, headers: &[(&str, &str)]) -> Exchange {
        let conn = ConnInfo {
            remote: format!("{}:40000", peer_literal(peer)).parse().unwrap(),
            local_port: 443,
            scheme: Scheme::Https,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:443".parse().unwrap(),
                kind: ListenerKind::Https,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        ex.req.set_line(b"GET", b"/", Version::Http11).unwrap();
        for (name, value) in headers {
            ex.req.push_field(name.as_bytes(), value.as_bytes());
        }
        ex
    }

    fn peer_literal(peer: &str) -> String {
        if peer.contains(':') {
            format!("[{peer}]")
        } else {
            peer.to_owned()
        }
    }

    /// The client address the plan settles on for a request from `peer`.
    fn client(plan: &TrustPlan, peer: &str, headers: &[(&str, &str)]) -> IpAddr {
        let mut ex = exchange(peer, headers);
        resolve(plan, &mut ex);
        ex.client
    }

    const CF: &[&str] = &["103.21.244.0/22", "2400:cb00::/32"];

    #[test]
    fn cf_connecting_ip_is_read_from_a_trusted_peer() {
        let plan = plan("CF-Connecting-IP", CF);
        assert_eq!(
            client(
                &plan,
                "103.21.244.9",
                &[("CF-Connecting-IP", "198.51.100.23")]
            ),
            ip("198.51.100.23")
        );
        assert_eq!(
            client(
                &plan,
                "2400:cb00::1",
                &[("cf-connecting-ip", "2001:db8::7")]
            ),
            ip("2001:db8::7"),
            "the header name is case-insensitive and the client may be IPv6"
        );
    }

    #[test]
    fn an_untrusted_peers_headers_are_ignored() {
        for header in ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"] {
            let plan = plan(header, CF);
            let spoof = [
                ("CF-Connecting-IP", "198.51.100.23"),
                ("X-Forwarded-For", "198.51.100.23"),
                ("X-Real-IP", "198.51.100.23"),
            ];
            assert_eq!(
                client(&plan, "203.0.113.5", &spoof),
                ip("203.0.113.5"),
                "{header} from a peer outside the trusted ranges"
            );
            assert_eq!(client(&plan, "2001:db8::5", &spoof), ip("2001:db8::5"));
        }
    }

    #[test]
    fn a_trusted_peer_without_the_header_is_its_own_client() {
        let plan = plan("CF-Connecting-IP", CF);
        assert_eq!(client(&plan, "103.21.244.9", &[]), ip("103.21.244.9"));
        assert_eq!(
            client(&plan, "103.21.244.9", &[("X-Real-IP", "198.51.100.23")]),
            ip("103.21.244.9"),
            "only the configured header counts"
        );
    }

    #[test]
    fn x_real_ip_is_read_from_a_trusted_peer() {
        let plan = plan("X-Real-IP", &["10.0.0.0/8"]);
        assert_eq!(
            client(&plan, "10.1.2.3", &[("X-Real-IP", "198.51.100.23")]),
            ip("198.51.100.23")
        );
        assert_eq!(
            client(&plan, "11.1.2.3", &[("X-Real-IP", "198.51.100.23")]),
            ip("11.1.2.3")
        );
    }

    #[test]
    fn a_single_address_header_must_hold_exactly_one_address() {
        let plan = plan("CF-Connecting-IP", &["10.0.0.0/8"]);
        let peer = ip("10.1.2.3");
        for value in [
            "",
            "unknown",
            "198.51.100.23, 198.51.100.24",
            "198.51.100.23,",
            "198.51.100.256",
            "198.51.100",
            "198.051.100.23",
            "fe80::1%eth0",
            "::1::2",
            "198.51.100.23 evil",
            "0x7f.0.0.1",
            "[198.51.100.23]",
            "1.2.3.4:",
            "1.2.3.4:99999",
            "1.2.3.4:+80",
        ] {
            assert_eq!(
                client(&plan, "10.1.2.3", &[("CF-Connecting-IP", value)]),
                peer,
                "{value:?} is not an address, so the peer stays the client"
            );
        }
        assert_eq!(
            client(
                &plan,
                "10.1.2.3",
                &[
                    ("CF-Connecting-IP", "198.51.100.23"),
                    ("CF-Connecting-IP", "198.51.100.24")
                ]
            ),
            peer,
            "a repeated field is ambiguous"
        );
    }

    #[test]
    fn addresses_with_a_port_or_brackets_are_read() {
        let plan = plan("CF-Connecting-IP", &["10.0.0.0/8"]);
        for (value, want) in [
            ("198.51.100.23:8443", "198.51.100.23"),
            ("[2001:db8::7]:8443", "2001:db8::7"),
            ("[2001:db8::7]", "2001:db8::7"),
            ("2001:DB8::7", "2001:db8::7"),
            ("  198.51.100.23\t", "198.51.100.23"),
        ] {
            assert_eq!(
                client(&plan, "10.1.2.3", &[("CF-Connecting-IP", value)]),
                ip(want),
                "{value:?}"
            );
        }
    }

    #[test]
    fn forwarded_addresses_that_map_an_ipv4_address_become_it() {
        let plan = plan("CF-Connecting-IP", &["10.0.0.0/8"]);
        assert_eq!(
            client(
                &plan,
                "10.1.2.3",
                &[("CF-Connecting-IP", "::ffff:198.51.100.23")]
            ),
            ip("198.51.100.23"),
            "`{{remote_host}}` and the log name the IPv4 address"
        );
    }

    #[test]
    fn a_mapped_peer_is_matched_against_ipv4_ranges() {
        let plan = plan("CF-Connecting-IP", &["10.0.0.0/8"]);
        assert_eq!(
            client(
                &plan,
                "::ffff:10.1.2.3",
                &[("CF-Connecting-IP", "198.51.100.23")]
            ),
            ip("198.51.100.23"),
            "a dual-stack listener reports IPv4 peers as mapped addresses"
        );
        assert_eq!(
            client(
                &plan,
                "::ffff:11.1.2.3",
                &[("CF-Connecting-IP", "198.51.100.23")]
            ),
            ip("::ffff:11.1.2.3"),
            "an untrusted peer is left as the listener reported it"
        );
    }

    #[test]
    fn x_forwarded_for_takes_the_rightmost_untrusted_address() {
        let plan = plan("X-Forwarded-For", &["10.0.0.0/8", "192.0.2.0/24"]);
        let xff = |value: &str| client(&plan, "10.0.0.1", &[("X-Forwarded-For", value)]);
        assert_eq!(xff("198.51.100.23"), ip("198.51.100.23"));
        assert_eq!(
            xff("1.1.1.1, 198.51.100.23, 10.0.0.9, 192.0.2.4"),
            ip("198.51.100.23"),
            "trusted hops on the right are skipped, and what the client wrote on the left is not read"
        );
        assert_eq!(
            xff("203.0.113.1, 203.0.113.2"),
            ip("203.0.113.2"),
            "the entry the trusted peer appended wins over the one it received"
        );
        assert_eq!(
            xff("10.9.9.9, 192.0.2.8"),
            ip("10.9.9.9"),
            "all trusted: the leftmost"
        );
        assert_eq!(xff(""), ip("10.0.0.1"), "an empty chain names no one");
        assert_eq!(
            xff(" , ,198.51.100.23 ,"),
            ip("198.51.100.23"),
            "empty entries are ignored"
        );
        assert_eq!(xff("198.51.100.23:51234, 10.0.0.9"), ip("198.51.100.23"));
    }

    #[test]
    fn x_forwarded_for_spans_repeated_fields() {
        let plan = plan("X-Forwarded-For", &["10.0.0.0/8"]);
        let two = [
            ("X-Forwarded-For", "9.9.9.9, 198.51.100.23"),
            ("X-Forwarded-For", "10.0.0.7"),
        ];
        assert_eq!(client(&plan, "10.0.0.1", &two), ip("198.51.100.23"));
        let split = [
            ("X-Forwarded-For", "198.51.100.23"),
            ("X-Forwarded-For", "10.0.0.7, 10.0.0.8"),
        ];
        assert_eq!(client(&plan, "10.0.0.1", &split), ip("198.51.100.23"));
    }

    #[test]
    fn x_forwarded_for_never_skips_a_value_it_cannot_read() {
        let plan = plan("X-Forwarded-For", &["10.0.0.0/8"]);
        let peer = ip("10.0.0.1");
        for chain in [
            "198.51.100.23, unknown",
            "198.51.100.23, unknown, 10.0.0.9",
            "198.51.100.23, 300.1.1.1",
            "198.51.100.23, _hidden, 10.0.0.9",
            "unknown",
        ] {
            assert_eq!(
                client(&plan, "10.0.0.1", &[("X-Forwarded-For", chain)]),
                peer,
                "{chain:?}: the part nearest the trusted peer is unreadable, so what lies left of it is not believed"
            );
        }
        assert_eq!(
            client(
                &plan,
                "10.0.0.1",
                &[("X-Forwarded-For", "unknown, 198.51.100.23")]
            ),
            ip("198.51.100.23"),
            "junk to the left of a readable untrusted address does not matter"
        );
    }

    #[test]
    fn x_forwarded_for_from_an_untrusted_peer_is_ignored() {
        let plan = plan("X-Forwarded-For", &["10.0.0.0/8"]);
        assert_eq!(
            client(
                &plan,
                "203.0.113.5",
                &[("X-Forwarded-For", "10.0.0.1, 1.2.3.4")]
            ),
            ip("203.0.113.5")
        );
    }

    #[test]
    fn cidr_lists_are_parsed_strictly() {
        for (text, want) in [
            ("10.0.0.0/8", "10.0.0.0/8"),
            ("192.0.2.7", "192.0.2.7/32"),
            ("0.0.0.0/0", "0.0.0.0/0"),
            ("2001:db8::/32", "2001:db8::/32"),
            ("2001:db8::1", "2001:db8::1/128"),
            ("::/0", "::/0"),
            ("::ffff:10.0.0.0/104", "10.0.0.0/8"),
            ("::ffff:192.0.2.7", "192.0.2.7/32"),
        ] {
            assert_eq!(Cidr::parse(text).unwrap().to_string(), want, "{text}");
        }
        for (text, why) in [
            ("10.0.0.0/33", "prefix length must be 0 to 32"),
            ("10.0.0.0/+8", "prefix length must be 0 to 32"),
            ("10.0.0.0/", "prefix length must be 0 to 32"),
            ("2001:db8::/129", "prefix length must be 0 to 128"),
            ("10.0.0.1/8", "write `10.0.0.0/8`"),
            ("2001:db8::1/32", "write `2001:db8::/32`"),
            ("example.com", "not an IP address"),
            ("10.0.0/8", "not an IP address"),
            ("", "not an IP address"),
            ("10.0.0.0/8/9", "prefix length must be 0 to 32"),
        ] {
            let err = Cidr::parse(text).expect_err(text);
            assert!(err.contains(why), "{text}: {err}");
        }
    }

    #[test]
    fn nets_merge_overlaps_and_answer_at_the_edges() {
        let set = nets(&[
            "10.0.0.0/9",
            "10.128.0.0/9",
            "10.64.0.0/10",
            "192.0.2.0/24",
            "192.0.2.77",
            "2001:db8::/32",
            "2001:db9::/32",
        ]);
        assert_eq!(set.v4.len(), 2, "10.0.0.0/8 and 192.0.2.0/24");
        assert_eq!(set.v6.len(), 1, "two adjacent /32s are one range");
        for inside in [
            "10.0.0.0",
            "10.255.255.255",
            "192.0.2.0",
            "192.0.2.255",
            "2001:db8::",
            "2001:db9:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(set.contains(ip(inside)), "{inside}");
        }
        for outside in [
            "9.255.255.255",
            "11.0.0.0",
            "192.0.1.255",
            "192.0.3.0",
            "0.0.0.0",
            "255.255.255.255",
            "2001:db7:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:dba::",
            "::1",
            "::",
        ] {
            assert!(!set.contains(ip(outside)), "{outside}");
        }
        assert!(!Nets::default().contains(ip("10.0.0.1")));
        let all = nets(&["0.0.0.0/0", "::/0"]);
        assert!(all.contains(ip("255.255.255.255")) && all.contains(ip("ffff::")));
    }

    #[test]
    fn the_cloudflare_preset_holds_its_published_ranges() {
        let set = Nets::new(cloudflare());
        for edge in [
            "173.245.48.1",
            "104.16.0.0",
            "104.23.255.255",
            "172.71.1.1",
            "131.0.72.9",
            "2606:4700::1111",
            "2a06:98c0::1",
        ] {
            assert!(set.contains(ip(edge)), "{edge} is a Cloudflare address");
        }
        for other in [
            "8.8.8.8",
            "104.15.255.255",
            "104.28.0.1",
            "2001:4860:4860::8888",
        ] {
            assert!(!set.contains(ip(other)), "{other} is not");
        }
        assert_eq!(
            cloudflare().count(),
            cloudflare::IPV4.len() + cloudflare::IPV6.len(),
            "every published range parses"
        );
    }

    #[test]
    fn header_names_are_the_three_that_hold_a_client() {
        for name in [
            "cf-connecting-ip",
            "CF-CONNECTING-IP",
            "X-Real-IP",
            "x-forwarded-for",
        ] {
            assert!(Header::parse(name).is_some(), "{name}");
        }
        for name in ["Forwarded", "True-Client-IP", "Host", ""] {
            assert!(Header::parse(name).is_none(), "{name}");
        }
    }

    fn forwarded(plan: &TrustPlan, peer: &str, headers: &[(&str, &str)]) -> String {
        let mut ex = exchange(peer, headers);
        resolve(plan, &mut ex);
        let t = Template::from_parts(vec![Part::Ph(Placeholder::ForwardedFor)]);
        let span = t.expand(&mut ex);
        String::from_utf8(ex.arena.get(span).to_vec()).unwrap()
    }

    #[test]
    fn the_upstream_chain_appends_the_peer_to_what_a_trusted_peer_sent() {
        let plan = plan("CF-Connecting-IP", CF);
        assert_eq!(
            forwarded(
                &plan,
                "103.21.244.9",
                &[
                    ("CF-Connecting-IP", "198.51.100.23"),
                    ("X-Forwarded-For", "198.51.100.23, 10.1.1.1"),
                    ("X-Forwarded-For", "10.2.2.2"),
                ]
            ),
            "198.51.100.23, 10.1.1.1, 10.2.2.2, 103.21.244.9"
        );
        let xff = self::plan("X-Forwarded-For", &["10.0.0.0/8"]);
        assert_eq!(
            forwarded(
                &xff,
                "10.0.0.1",
                &[("X-Forwarded-For", "198.51.100.23, 10.0.0.9")]
            ),
            "198.51.100.23, 10.0.0.9, 10.0.0.1"
        );
    }

    #[test]
    fn the_upstream_chain_of_an_untrusted_peer_is_the_peer_alone() {
        let plan = plan("X-Forwarded-For", &["10.0.0.0/8"]);
        assert_eq!(
            forwarded(
                &plan,
                "203.0.113.5",
                &[("X-Forwarded-For", "10.0.0.1, 1.2.3.4")]
            ),
            "203.0.113.5",
            "a client cannot plant addresses in the chain the origin reads"
        );
        assert_eq!(forwarded(&plan, "203.0.113.5", &[]), "203.0.113.5");
        assert_eq!(
            forwarded(&plan, "2001:db8::5", &[("X-Forwarded-For", "1.2.3.4")]),
            "2001:db8::5"
        );
    }

    #[test]
    fn a_trusted_peer_with_nothing_to_forward_is_the_whole_chain() {
        let plan = plan("CF-Connecting-IP", CF);
        assert_eq!(forwarded(&plan, "103.21.244.9", &[]), "103.21.244.9");
        assert_eq!(
            forwarded(&plan, "::ffff:103.21.244.9", &[]),
            "103.21.244.9",
            "a mapped peer is written as the IPv4 address"
        );
    }

    #[test]
    fn peer_host_stays_the_peer_and_remote_host_the_client() {
        let plan = plan("CF-Connecting-IP", CF);
        let mut ex = exchange("103.21.244.9", &[("CF-Connecting-IP", "198.51.100.23")]);
        resolve(&plan, &mut ex);
        let t = Template::from_parts(vec![
            Part::Ph(Placeholder::RemoteHost),
            Part::Lit(b" ".as_slice().into()),
            Part::Ph(Placeholder::PeerHost),
        ]);
        let span = t.expand(&mut ex);
        assert_eq!(ex.arena.get(span), b"198.51.100.23 103.21.244.9");
    }

    #[test]
    fn resolving_and_forwarding_allocate_nothing_after_warm_up() {
        let plan = plan("X-Forwarded-For", &["10.0.0.0/8", "2400:cb00::/32"]);
        let t = Template::from_parts(vec![Part::Ph(Placeholder::ForwardedFor)]);
        let mut cases = [
            exchange(
                "10.0.0.1",
                &[
                    ("X-Forwarded-For", "198.51.100.23, 10.0.0.9"),
                    ("X-Real-IP", "1.1.1.1"),
                ],
            ),
            exchange("2400:cb00::1", &[("X-Forwarded-For", "2001:db8::7")]),
            exchange("203.0.113.5", &[("X-Forwarded-For", "10.0.0.1")]),
            exchange("10.0.0.1", &[("X-Forwarded-For", "x, y, z")]),
        ];
        for ex in &mut cases {
            resolve(&plan, ex);
            t.expand(ex);
        }
        let before = crate::runtime::testing::thread_allocations();
        for _ in 0..1_000 {
            for ex in &mut cases {
                ex.arena.clear();
                resolve(&plan, ex);
                t.expand(ex);
            }
        }
        assert_eq!(
            crate::runtime::testing::thread_allocations(),
            before,
            "every case, trusted or not, valid or not"
        );
    }

    /// The cost of resolving the client of one request, for `cargo test --release`. Run with
    /// `cargo test --release --lib trust::tests::cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn cost_per_request() {
        use std::hint::black_box;
        use std::time::Instant;
        let cloudflare = TrustPlan::new(
            Nets::new(cloudflare()),
            Header::parse("CF-Connecting-IP").unwrap(),
        );
        let xff = TrustPlan::new(Nets::new(cloudflare_and_private()), Header::ForwardedFor);
        let browser = [
            ("Host", "app.example.com"),
            (
                "User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/131.0",
            ),
            ("Accept", "application/json"),
            ("Accept-Encoding", "gzip, br"),
            ("Cookie", "session=0123456789abcdef; theme=dark"),
        ];
        let with = |extra: &[(&'static str, &'static str)]| -> Vec<(&'static str, &'static str)> {
            browser.iter().chain(extra).copied().collect()
        };
        let cases: [(&str, &TrustPlan, Exchange); 5] = [
            (
                "cf-connecting-ip, trusted edge",
                &cloudflare,
                exchange(
                    "173.245.48.9",
                    &with(&[("CF-Connecting-IP", "198.51.100.23")]),
                ),
            ),
            (
                "cf-connecting-ip, IPv6 edge and client",
                &cloudflare,
                exchange(
                    "2606:4700::1111",
                    &with(&[("CF-Connecting-IP", "2001:db8::7")]),
                ),
            ),
            (
                "x-forwarded-for, 3 entries",
                &xff,
                exchange(
                    "10.0.0.1",
                    &with(&[("X-Forwarded-For", "198.51.100.23, 172.70.1.1, 10.0.0.9")]),
                ),
            ),
            (
                "untrusted peer",
                &cloudflare,
                exchange("203.0.113.5", &with(&[("CF-Connecting-IP", "1.2.3.4")])),
            ),
            (
                "trusted, no header",
                &cloudflare,
                exchange("173.245.48.9", &with(&[])),
            ),
        ];
        let rounds = 20_000_000u32;
        for (label, plan, mut ex) in cases {
            let start = Instant::now();
            for _ in 0..rounds {
                ex.client = ex.conn.remote.ip();
                resolve(black_box(plan), black_box(&mut ex));
                black_box(ex.client);
            }
            let ns = start.elapsed().as_nanos() as f64 / f64::from(rounds);
            println!("resolve, {label}: {ns:.1} ns");
        }
        let mut ex = exchange(
            "173.245.48.9",
            &with(&[
                ("CF-Connecting-IP", "198.51.100.23"),
                ("X-Forwarded-For", "198.51.100.23"),
            ]),
        );
        resolve(&cloudflare, &mut ex);
        let t = Template::from_parts(vec![Part::Ph(Placeholder::ForwardedFor)]);
        let start = Instant::now();
        for _ in 0..rounds {
            ex.arena.clear();
            black_box(t.expand(black_box(&mut ex)));
        }
        let ns = start.elapsed().as_nanos() as f64 / f64::from(rounds);
        println!("upstream X-Forwarded-For expansion: {ns:.1} ns");
    }

    fn cloudflare_and_private() -> impl Iterator<Item = Cidr> {
        cloudflare().chain(
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].map(|r| Cidr::parse(r).unwrap()),
        )
    }
}
