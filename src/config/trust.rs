//! The schema of `trustedProxies`: which peers may tell this proxy the client's address, and
//! in which header.

use serde::Deserialize;

/// `trustedProxies = { from = ["cloudflare", "10.0.0.0/8"], header = "CF-Connecting-IP" }`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustSpec {
    /// CIDR ranges of the peers whose header is believed, or `cloudflare` for Cloudflare's
    /// published ranges.
    pub from: Vec<String>,
    /// The field that holds the client address: `CF-Connecting-IP`, `X-Real-IP`, or
    /// `X-Forwarded-For` (its rightmost address that is not itself a trusted proxy).
    pub header: String,
}
