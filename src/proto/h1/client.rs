//! HTTP/1.1 towards upstreams: request head serialisation from an `Exchange`, response head
//! reading. The proxy drives the IO; this module only knows the format.

use crate::exchange::Exchange;
use crate::plan::{ProxyPlan, UpstreamPlan};

/// Framing of the request body as sent upstream.
#[derive(Clone, Copy, Debug)]
pub(crate) enum UpFraming {
    None,
    Length(u64),
    /// h1 chunked client body forwarded unchanged.
    ChunkedPassthrough,
    /// h2/h3 body without content-length: we chunk it.
    Chunked,
}

/// Writes the upstream request head into `ex.out`:
/// - request line: method, `ex.req.write_upstream_target`, `HTTP/1.1`;
/// - every live client field except hop-by-hop ones, those named in `Connection`, `Expect`,
///   and the ones the proxy plan sets or removes;
/// - the plan's header ops (defaults X-Forwarded-For/-Proto/-Host first, then the config's),
///   values expanded from templates;
/// - framing, and `Connection: upgrade` + `Upgrade` copied when the client asked to upgrade.
///
/// Host is the client's (passed through unchanged).
pub(crate) fn write_request_head(
    ex: &mut Exchange,
    proxy: &ProxyPlan,
    up: &UpstreamPlan,
    framing: UpFraming,
    upgrade: bool,
) {
    todo!()
}
