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
/// hash the client address's octets (IPv4, or IPv6 or its /64), constants are precomputed and
/// the same under every seed, templates expand into the arena and hash its bytes. `None` for
/// an empty expansion: the request has no key.
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

    #[test]
    fn an_empty_expansion_is_no_key() {
        let key = template("{cookie.cart}");
        assert_eq!(hash(&key, &mut exchange("192.0.2.1"), 0), None);
        let mut ex = exchange("192.0.2.1");
        ex.req.push_field(b"Cookie", b"cart=42");
        assert!(hash(&key, &mut ex, 0).is_some());
    }
}
