//! Host -> site, per listener: exact names by binary search, then `*.suffix` wildcards
//! (one label, longest suffix first), then `*`. The request head stores its host lowercased
//! without port or trailing dot, so a lookup compares bytes and allocates nothing.

use super::SiteId;

#[derive(Debug, Default)]
pub(crate) struct HostIndex {
    /// Sorted by name.
    exact: Box<[(Box<[u8]>, SiteId)]>,
    /// `.suffix` with its leading dot, longest first.
    suffixes: Box<[(Box<[u8]>, SiteId)]>,
    any: Option<SiteId>,
}

/// One host pattern of a site, as the compiler validated it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostPattern {
    Exact(Box<[u8]>),
    /// `*.example.com`, stored as `.example.com`.
    Suffix(Box<[u8]>),
    Any,
}

impl HostPattern {
    /// Lowercases and validates a configured host name. `None` for an empty name, a port, a
    /// `*` anywhere but a whole first label, or a byte that cannot be in a host.
    pub fn parse(name: &str) -> Option<HostPattern> {
        let lower = name.to_ascii_lowercase();
        if lower == "*" {
            return Some(HostPattern::Any);
        }
        let (wild, rest) = match lower.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, lower.as_str()),
        };
        let ok = !rest.is_empty()
            && !rest.starts_with('.')
            && !rest.ends_with('.')
            && !rest.contains("..")
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
        let ip6 = !wild && rest.starts_with('[') && rest.ends_with(']');
        if !ok && !ip6 {
            return None;
        }
        Some(if wild {
            HostPattern::Suffix(format!(".{rest}").into_bytes().into())
        } else {
            HostPattern::Exact(rest.as_bytes().into())
        })
    }
}

impl std::fmt::Display for HostPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostPattern::Exact(name) => f.write_str(&String::from_utf8_lossy(name)),
            HostPattern::Suffix(suffix) => write!(f, "*{}", String::from_utf8_lossy(suffix)),
            HostPattern::Any => f.write_str("*"),
        }
    }
}

impl HostIndex {
    /// Builds the index from patterns the compiler has made unique per listener.
    pub fn new(patterns: impl IntoIterator<Item = (HostPattern, SiteId)>) -> HostIndex {
        let mut exact: Vec<(Box<[u8]>, SiteId)> = Vec::new();
        let mut suffixes: Vec<(Box<[u8]>, SiteId)> = Vec::new();
        let mut any = None;
        for (pattern, site) in patterns {
            match pattern {
                HostPattern::Any => any = any.or(Some(site)),
                HostPattern::Exact(name) => exact.push((name, site)),
                HostPattern::Suffix(suffix) => suffixes.push((suffix, site)),
            }
        }
        exact.sort_by(|a, b| a.0.cmp(&b.0));
        suffixes.sort_by_key(|s| std::cmp::Reverse(s.0.len()));
        HostIndex {
            exact: exact.into(),
            suffixes: suffixes.into(),
            any,
        }
    }

    /// `host` is lowercase, without port or trailing dot (as `RequestHead::host` keeps it).
    pub fn lookup(&self, host: &[u8]) -> Option<SiteId> {
        if let Ok(i) = self.exact.binary_search_by(|(k, _)| (**k).cmp(host)) {
            return Some(self.exact[i].1);
        }
        let first_dot = memchr::memchr(b'.', host);
        if let Some(dot) = first_dot.filter(|&d| d > 0) {
            let tail = &host[dot..];
            if let Some((_, site)) = self.suffixes.iter().find(|(s, _)| **s == *tail) {
                return Some(*site);
            }
        }
        self.any
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(patterns: &[(&str, u16)]) -> HostIndex {
        HostIndex::new(
            patterns
                .iter()
                .map(|&(p, s)| (HostPattern::parse(p).unwrap(), SiteId(s))),
        )
    }

    #[test]
    fn exact_then_one_label_wildcard_then_any() {
        let idx = index(&[
            ("Example.org", 0),
            ("*.example.org", 1),
            ("www.example.org", 2),
            ("*", 3),
        ]);
        assert_eq!(idx.lookup(b"example.org"), Some(SiteId(0)));
        assert_eq!(idx.lookup(b"www.example.org"), Some(SiteId(2)));
        assert_eq!(idx.lookup(b"blog.example.org"), Some(SiteId(1)));
        assert_eq!(idx.lookup(b"a.b.example.org"), Some(SiteId(3)));
        assert_eq!(idx.lookup(b".example.org"), Some(SiteId(3)));
        assert_eq!(idx.lookup(b""), Some(SiteId(3)));
        let idx = index(&[("example.org", 0)]);
        assert_eq!(idx.lookup(b"other.org"), None);
        assert_eq!(idx.lookup(b""), None);
    }

    #[test]
    fn invalid_patterns() {
        for bad in ["", "a:80", "a.*.b", "*a.b", "a..b", ".a", "*.", "a b"] {
            assert_eq!(HostPattern::parse(bad), None, "{bad:?}");
        }
        assert_eq!(
            HostPattern::parse("[::1]"),
            Some(HostPattern::Exact(Box::from(&b"[::1]"[..])))
        );
    }
}
