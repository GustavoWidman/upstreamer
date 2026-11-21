//! Request keys: what `balance.hash` and `limit.key` group requests by. Both features read
//! keys, so neither owns the other's input.

use crate::exchange::Exchange;
use crate::plan::KeyPlan;
use rustc_hash::FxHasher;
use std::hash::Hasher;
use std::net::IpAddr;

/// The seed of hashes that must agree everywhere: a consistent-hash key reaches the same
/// origin on every core, after a restart, and on every replica with the same members. Limits
/// use a seed random per process instead, so a client cannot aim its key at another's bucket.
pub(crate) const FIXED_SEED: u64 = 0;

/// The 64-bit hash of a request's key, without allocating: `{remote_host}` and `{remote_net}`
/// hash the client address's octets (IPv4, or IPv6 or its /64), `{header.Name}` hashes the
/// field's value in the header block, constants are precomputed and the same under every seed,
/// templates expand into the arena and hash its bytes. `None` for an empty expansion: the
/// request has no key. Every form hashes the bytes its template would expand to, so a key
/// selects the same bucket and the same origin whichever form the compiler picked.
pub(crate) fn hash(key: &KeyPlan, ex: &mut Exchange, seed: u64) -> Option<u64> {
    let mut h = FxHasher::with_seed(seed as usize);
    match key {
        KeyPlan::RemoteHost => match ex.client.to_canonical() {
            IpAddr::V4(a) => h.write(&a.octets()),
            IpAddr::V6(a) => h.write(&a.octets()),
        },
        KeyPlan::RemoteNet => match ex.client.to_canonical() {
            IpAddr::V4(a) => h.write(&a.octets()),
            IpAddr::V6(a) => h.write(&a.octets()[..8]),
        },
        KeyPlan::Const(hash) => return Some(*hash),
        KeyPlan::Header(name) => {
            let (req, arena) = (&ex.req, &mut ex.arena);
            let mut values = req.fields.values(name);
            let first = values.next().filter(|v| !v.is_empty());
            if values.next().is_none() {
                h.write(first?);
            } else {
                // A repeated field: its values joined with ", ", as `{header.Name}` expands.
                let span = arena.build(|out| {
                    for (i, v) in req.fields.values(name).enumerate() {
                        if i > 0 {
                            out.extend_from_slice(b", ");
                        }
                        out.extend_from_slice(v);
                    }
                });
                h.write(arena.get(span));
            }
        }
        KeyPlan::Template(t) => {
            let span = t.expand(ex);
            let bytes = ex.arena.get(span);
            if bytes.is_empty() {
                return None;
            }
            h.write(bytes);
        }
    }
    Some(h.finish())
}

/// The hash of a constant key, computed once by the compiler.
pub(crate) fn constant(bytes: &[u8]) -> u64 {
    let mut h = FxHasher::with_seed(FIXED_SEED as usize);
    h.write(bytes);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ConnInfo, Proto, Scheme};
    use crate::plan::template::{Captures, Scope, Template};
    use crate::plan::{ListenerKey, ListenerKind};

    fn exchange(client: &str) -> Exchange {
        let conn = ConnInfo {
            remote: "192.0.2.1:5000".parse().unwrap(),
            local_port: 80,
            scheme: Scheme::Http,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:80".parse().unwrap(),
                kind: ListenerKind::Http,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        ex.client = client.parse().unwrap();
        ex.req
            .set_line(b"GET", b"/", crate::msg::Version::Http11)
            .unwrap();
        ex
    }

    fn template(src: &str) -> KeyPlan {
        let mut vars = Vec::new();
        let mut scope = Scope {
            vars: &mut vars,
            captures: Captures::Unavailable,
            in_error_route: false,
            uses_captures: false,
            reads: Vec::new(),
        };
        KeyPlan::Template(Template::parse(src, &mut scope).unwrap())
    }

    #[test]
    fn remote_net_groups_an_ipv6_64_and_keeps_ipv4_hosts_apart() {
        let net = |ip: &str| hash(&KeyPlan::RemoteNet, &mut exchange(ip), 7);
        let host = |ip: &str| hash(&KeyPlan::RemoteHost, &mut exchange(ip), 7);
        assert_eq!(net("2001:db8:1:2::1"), net("2001:db8:1:2:ffff::9"));
        assert_ne!(net("2001:db8:1:2::1"), net("2001:db8:1:3::1"));
        assert_ne!(host("2001:db8:1:2::1"), host("2001:db8:1:2:ffff::9"));
        assert_ne!(net("192.0.2.1"), net("192.0.2.2"));
        assert_eq!(
            net("::ffff:192.0.2.1"),
            net("192.0.2.1"),
            "a mapped IPv4 is its IPv4"
        );
        assert_eq!(host("192.0.2.1"), net("192.0.2.1"));
    }

    #[test]
    fn the_seed_separates_processes_except_for_constants() {
        let key = template("{header.x-api-key}");
        let mut ex = exchange("192.0.2.1");
        ex.req.push_field(b"X-Api-Key", b"k1");
        let a = hash(&key, &mut ex, 1);
        assert_eq!(a, hash(&key, &mut ex, 1));
        assert_ne!(a, hash(&key, &mut ex, 2));
        let constant = KeyPlan::Const(constant(b"all"));
        assert_eq!(
            hash(&constant, &mut ex, 1),
            hash(&constant, &mut ex, 2),
            "one bucket, one origin, whatever the seed"
        );
    }

    /// A request header: name, value.
    type Field<'a> = (&'a [u8], &'a [u8]);

    /// The hash of `{header.<name>}` through the header fast path and through the template,
    /// on a request carrying `fields`, under a fixed and a per-process seed.
    fn header_both_ways(name: &str, fields: &[Field]) -> [(Option<u64>, Option<u64>); 2] {
        let direct = KeyPlan::Header(crate::msg::HeaderName::new(name).unwrap());
        let expanded = template(&format!("{{header.{name}}}"));
        let mut ex = exchange("192.0.2.1");
        for (n, v) in fields {
            ex.req.push_field(n, v);
        }
        [FIXED_SEED, 0x5eed]
            .map(|seed| (hash(&direct, &mut ex, seed), hash(&expanded, &mut ex, seed)))
    }

    #[test]
    fn a_header_key_hashes_what_its_template_expands_to() {
        let cases: &[(&str, &[Field])] = &[
            ("X-Client", &[(b"X-Client", b"c17")]),
            ("x-client", &[(b"X-CLIENT", b"c17"), (b"Accept", b"*/*")]),
            ("X-Client", &[(b"x-client", b"c17")]),
            (
                "X-Client",
                &[
                    (b"X-Client", b"a"),
                    (b"Accept", b"*/*"),
                    (b"X-Client", b"b"),
                ],
            ),
            ("X-Client", &[(b"X-Client", b""), (b"X-Client", b"b")]),
            ("X-Client", &[(b"X-Client", b"a"), (b"X-Client", b"")]),
            ("X-Forwarded-For", &[(b"X-Forwarded-For", b"10.0.0.1")]),
            ("Cookie", &[(b"Cookie", b"a=1"), (b"Cookie", b"b=2")]),
        ];
        for (name, fields) in cases {
            for (direct, expanded) in header_both_ways(name, fields) {
                assert!(direct.is_some(), "{name} {fields:?} has a key");
                assert_eq!(direct, expanded, "{name} {fields:?}");
            }
        }
    }

    #[test]
    fn a_missing_or_empty_header_is_no_key_either_way() {
        let cases: &[(&str, &[Field])] = &[
            ("X-Client", &[]),
            ("X-Client", &[(b"X-Clients", b"c1"), (b"Accept", b"*/*")]),
            ("X-Client", &[(b"X-Client", b"")]),
            ("Cookie", &[(b"X-Client", b"c1")]),
        ];
        for (name, fields) in cases {
            for (direct, expanded) in header_both_ways(name, fields) {
                assert_eq!(direct, None, "{name} {fields:?}");
                assert_eq!(expanded, None, "{name} {fields:?}");
            }
        }
    }

    #[test]
    fn a_header_key_tells_values_apart_and_ignores_the_names_case() {
        let one = |n: &[u8], v: &[u8]| header_both_ways("x-client", &[(n, v)])[0].0;
        assert_eq!(one(b"X-Client", b"c1"), one(b"x-cLiEnT", b"c1"));
        assert_ne!(one(b"X-Client", b"c1"), one(b"X-Client", b"C1"));
        assert_ne!(one(b"X-Client", b"c1"), one(b"X-Client", b"c2"));
    }

    #[test]
    fn an_empty_expansion_is_no_key() {
        let key = template("{cookie.cart}");
        assert_eq!(hash(&key, &mut exchange("192.0.2.1"), 0), None);
        let mut ex = exchange("192.0.2.1");
        ex.req.push_field(b"Cookie", b"cart=42");
        assert!(hash(&key, &mut ex, 0).is_some());
    }
}
