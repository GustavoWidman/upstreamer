//! Reverse proxy to one HTTP/1.1 origin (cleartext or TLS). The request's own task owns the
//! upstream connection for the duration of the exchange: checked out of the core-local pool,
//! written and read inline, checked back in when the response body ends cleanly.
//!
//! Retry: a pooled connection that fails before any response byte arrived (the origin closed
//! it while idle) is retried once on a freshly dialled connection, if the method is idempotent
//! or the body is replayable. Never otherwise.
//!
//! Errors map to statuses that go through the site's error routes: dial failure or reset
//! before the head -> 502, response-header timeout -> 504.

pub(crate) mod pool;
pub(crate) mod relay;

use crate::body::RequestBody;
use crate::exchange::Exchange;
use crate::msg::Status;
use crate::net::Transport;
use crate::pipeline::Response;
use crate::plan::{ProxyPlan, UpstreamId, UpstreamPlan};
use crate::proto::h1::client::{self, UpFraming};
use crate::proto::h1::codec::{Chunked, Framing};
use crate::runtime::{Core, CoreSnapshot};
use bytes::BytesMut;
use std::time::{Duration, Instant};

/// A connection to an origin. Owned by exactly one request while checked out, by the core's
/// pool while idle; never shared.
pub(crate) struct UpstreamConn {
    pub io: Transport,
    /// Lent from the core's buffer pool while checked out; `None` while pooled.
    pub buf: Option<BytesMut>,
    pub upstream: UpstreamId,
    /// Plan generation it was dialled under; a conn from an older generation whose origin
    /// changed is closed instead of pooled.
    pub generation: u64,
    pub idle_since: Instant,
    pub requests: u32,
}

/// The response body still on the upstream connection.
pub(crate) struct UpstreamBody {
    pub conn: UpstreamConn,
    pub framing: Framing,
    pub chunked: Chunked,
    pub remaining: u64,
    /// The origin allows reuse (no `Connection: close`, HTTP/1.1, framing not EOF).
    pub reusable: bool,
}

impl UpstreamBody {
    /// Ends the body: back to the pool if fully read and reusable, else closed.
    pub fn finish(self, core: &Core) {
        todo!()
    }
}

/// An upgraded upstream connection (101) for the h1 driver to tunnel to.
pub(crate) struct Upgrade {
    pub conn: UpstreamConn,
    pub idle: Option<Duration>,
}

#[derive(Debug)]
pub(crate) enum ProxyError {
    Dial(std::io::Error),
    DialTimeout,
    Tls(std::io::Error),
    ResponseHeaderTimeout,
    /// Reset or EOF before a complete response head.
    Upstream(std::io::Error),
    BadResponse,
    /// The client went away while the request body was being forwarded.
    ClientGone,
}

impl ProxyError {
    pub fn status(&self) -> Status {
        match self {
            ProxyError::DialTimeout | ProxyError::ResponseHeaderTimeout => Status::GATEWAY_TIMEOUT,
            _ => Status::BAD_GATEWAY,
        }
    }
}

/// Hot path:
/// 1. serialise the upstream request head into `ex.out` (`client::write_request_head`);
/// 2. take a pooled connection or [`dial`];
/// 3. [`attempt`]: send head + body, read the response head;
/// 4. retry once on a fresh connection only if the pooled one failed before any response
///    byte and the request can be replayed.
pub(crate) async fn forward(
    core: &Core,
    snap: &CoreSnapshot,
    plan: &ProxyPlan,
    ex: &mut Exchange,
    mut body: RequestBody<'_>,
) -> Result<Response, ProxyError> {
    let up = &snap.plan.upstreams[plan.upstream.0 as usize];
    let upgrade = wants_upgrade(ex);
    client::write_request_head(ex, plan, up, up_framing(&body), upgrade);

    let mut fresh = false;
    loop {
        let conn = match (fresh, core.upstreams.checkout(up.id, Instant::now())) {
            (false, Some(conn)) => conn,
            _ => {
                fresh = true;
                dial(core, up, plan.dial_timeout).await?
            }
        };
        match attempt(core, plan, ex, &mut body, conn).await {
            Ok(resp) => return Ok(resp),
            Err(Failed {
                error,
                replayable: true,
            }) if !fresh && (ex.req.method.idempotent() || body.replayable()) => {
                fresh = true;
            }
            Err(Failed { error, .. }) => return Err(error),
        }
    }
}

/// One try on one connection. The connection moves into the response body (or the upgrade)
/// on success and is dropped (closed) on failure.
async fn attempt(
    core: &Core,
    plan: &ProxyPlan,
    ex: &mut Exchange,
    body: &mut RequestBody<'_>,
    conn: UpstreamConn,
) -> Result<Response, Failed> {
    // writev(ex.out + buffered body) -> relay::copy_request (or chunk loop for h2/h3 bodies)
    // -> read head with plan.response_header_timeout -> codec::parse_response into a
    // ResponseHead -> 101: Response { upgrade } / else Body::Upstream(UpstreamBody { conn, .. })
    todo!()
}

/// `replayable`: nothing of the response had arrived, so the request may be sent again.
struct Failed {
    error: ProxyError,
    replayable: bool,
}

fn wants_upgrade(ex: &Exchange) -> bool {
    todo!("h1 request with Connection: upgrade and an Upgrade header")
}

fn up_framing(body: &RequestBody<'_>) -> UpFraming {
    todo!()
}

/// Dials an origin: resolve (core cache, `getaddrinfo` on the blocking pool on a miss), TCP
/// connect with TCP_NODELAY within the dial timeout, TLS handshake when `up.tls` (session
/// resumption through the client config's cache).
pub(crate) async fn dial(
    core: &Core,
    up: &UpstreamPlan,
    timeout: Duration,
) -> Result<UpstreamConn, ProxyError> {
    todo!()
}
