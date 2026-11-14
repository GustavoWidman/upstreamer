//! HTTP/1.1 towards upstreams: the request head as the origin gets it. The proxy drives the
//! IO; this module only knows which fields go out.

use crate::exchange::Exchange;
use crate::plan::ProxyPlan;
use crate::proto::h1::codec::{self, OutFraming};

/// Writes the upstream request head into `ex.out`, replacing what was there:
/// - the proxy plan's header ops are applied to the request's fields first (the defaults
///   X-Forwarded-For/-Proto/-Host, then the config's), values expanded from templates;
/// - request line: method, `RequestHead::write_upstream_target`, `HTTP/1.1`;
/// - every live field except hop-by-hop ones, those named in `Connection`, and `Expect`;
/// - framing, and `Connection: upgrade` + `Upgrade` copied when the client asked to upgrade.
///
/// Host is the client's, passed through unchanged, unless an op sets it.
pub(crate) fn write_request_head(
    ex: &mut Exchange,
    proxy: &ProxyPlan,
    framing: OutFraming,
    upgrade: bool,
) {
    for op in proxy.headers.iter() {
        match &op.value {
            None => ex.req.fields.remove(&op.name),
            Some(template) => {
                let value = template.expand(ex);
                ex.req.fields.set(&op.name, ex.arena.get(value));
            }
        }
    }
    ex.out.clear();
    codec::write_request_head(&ex.req, framing, upgrade, &mut ex.out);
}
