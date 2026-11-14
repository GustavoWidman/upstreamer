//! Reverse proxy to one HTTP/1.1 origin (cleartext or TLS). The request's own task owns the
//! upstream connection for the duration of the exchange: checked out of the core-local pool,
//! written and read inline, checked back in when the response body ends cleanly.
//!
//! Retry: a pooled connection that fails before any byte of the response arrived (the origin
//! closed it while idle) is retried once on a freshly dialled connection, when the method is
//! idempotent and no body byte was consumed. Never otherwise.
//!
//! Errors map to statuses that go through the site's error routes: dial failure or reset
//! before the head -> 502, dial or response-header timeout -> 504.
//!
//! A client that goes away is noticed while its request body is being read, while a response
//! body is being relayed, and once the origin has taken a second to start its answer. Each
//! closes the origin's connection. A client that only closes its sending side counts as gone.

pub(crate) mod conn;
pub(crate) mod pool;
pub(crate) mod relay;
pub(crate) mod timer;
pub(crate) mod tls;

pub(crate) use conn::{UpstreamConn, UpstreamIo};

use crate::body::{Body, RequestBody};
use crate::exchange::{Exchange, Proto};
use crate::msg::{Known, Method, ResponseHead, Status, Version};
use crate::net::{Socket, Transport};
use crate::pipeline::Response;
use crate::plan::{OriginAddr, ProxyPlan, UpstreamPlan};
use crate::proto::h1::client;
use crate::proto::h1::codec::{self, Limits, OutFraming, Parsed};
use crate::runtime::{Core, CoreSnapshot};
use bytes::{Buf, Bytes, BytesMut};
use relay::{Sent, Tracker};
use rustls::pki_types::ServerName;
use smallvec::SmallVec;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::net::{SocketAddr, ToSocketAddrs};
use std::task::Poll;
use std::time::{Duration, Instant};
use timer::Deadline;

/// Field slots of the head parser: a response may carry as many fields as it can take.
const MAX_RESPONSE_FIELDS: u16 = 256;

/// The response body still on the upstream connection.
pub(crate) struct UpstreamBody {
    pub conn: UpstreamConn,
    /// Follows the body through the connection's bytes, those in `conn.buf` included.
    pub track: Tracker,
    /// The origin allows reuse (no `Connection: close`, HTTP/1.1, framing not EOF) and got
    /// the whole request.
    pub reusable: bool,
}

impl UpstreamBody {
    /// The body's length, when the origin declared one.
    pub fn len(&self) -> Option<u64> {
        self.track.remaining()
    }

    /// Ends the body: back to the pool if fully read and reusable, else closed.
    pub fn finish(self, core: &Core) {
        let UpstreamBody {
            mut conn,
            track,
            reusable,
        } = self;
        let leftover = !conn.buf.is_empty();
        core.bufs.put(std::mem::take(&mut conn.buf));
        if !reusable || !track.ended() || leftover {
            return;
        }
        let snap = core.snapshot();
        if conn.generation == snap.plan.generation {
            let up = &snap.plan.upstreams[conn.upstream.0 as usize];
            core.upstreams.checkin(conn, up);
        }
    }

    /// The next piece of body data, without chunk syntax; `None` at the end.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        let UpstreamBody { conn, track, .. } = self;
        loop {
            let data = relay::take_data(track, &mut conn.buf)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            if data.is_some() || track.ended() {
                return Ok(data);
            }
            if conn.io.read(&mut conn.buf).await? == 0 && !track.close() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

/// An upgraded upstream connection (101) for the h1 driver to tunnel to.
pub(crate) struct Upgrade {
    pub conn: UpstreamConn,
    pub idle: Option<Duration>,
}

#[derive(Debug)]
pub(crate) enum ProxyError {
    Dial(io::Error),
    DialTimeout,
    Tls(io::Error),
    ResponseHeaderTimeout,
    /// Reset or EOF before a complete response head.
    Upstream(io::Error),
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
    client::write_request_head(ex, plan, up_framing(&body), upgrade);

    let mut pooled = core.upstreams.checkout(up, snap.plan.generation);
    loop {
        let reused = pooled.is_some();
        let mut conn = match pooled.take() {
            Some(conn) => conn,
            None => dial(core, up, snap.plan.generation, plan.dial_timeout).await?,
        };
        conn.buf = core.bufs.take();
        match attempt(core, snap, plan, ex, &mut body, conn, upgrade).await {
            Ok(resp) => return Ok(resp),
            Err(Failed {
                replayable: true, ..
            }) if reused && ex.req.method.idempotent() && body.replayable() => {}
            Err(Failed { error, .. }) => return Err(error),
        }
    }
}

/// One try on one connection. The connection moves into the response body (or the upgrade)
/// on success and is closed on failure.
async fn attempt(
    core: &Core,
    snap: &CoreSnapshot,
    plan: &ProxyPlan,
    ex: &mut Exchange,
    body: &mut RequestBody<'_>,
    mut conn: UpstreamConn,
    upgrade: bool,
) -> Result<Response, Failed> {
    let sent = match &mut *body {
        RequestBody::H1(body) if !body.state.is_empty() => {
            relay::copy_request(core, &ex.out, body, &mut conn).await
        }
        RequestBody::Empty | RequestBody::H1(_) => {
            // A failed write shows as a failed read of the response just below.
            let _ = conn
                .io
                .write_all_vectored(&mut [IoSlice::new(&ex.out)])
                .await;
            Ok(Sent::All)
        }
        body => send_chunks(&ex.out, body, &mut conn).await,
    };
    let sent = match sent {
        Ok(sent) => sent,
        Err(_) => return Err(conn.fail(core, ProxyError::ClientGone)),
    };

    let limits = Limits {
        max_head_bytes: snap.plan.server.max_head_bytes,
        max_header_fields: MAX_RESPONSE_FIELDS,
    };
    let mut head = ex.response_head(Status::OK);
    let client = match &mut *body {
        RequestBody::H1(body) => Some((&mut *body.io, &mut *body.buf)),
        _ => None,
    };
    let read = read_head(
        &mut conn,
        &limits,
        ex.req.method,
        plan.response_header_timeout,
        client,
        &mut head,
    )
    .await;
    let (framing, keep_alive) = match read {
        Ok(read) => read,
        Err(error) => {
            ex.recycle(head);
            if let (ProxyError::ClientGone, RequestBody::H1(body)) = (&error, body) {
                body.state.failed = true;
            }
            return Err(conn.fail(core, error));
        }
    };

    if head.status == Status::SWITCHING_PROTOCOLS {
        if !upgrade {
            ex.recycle(head);
            return Err(conn.fail(core, ProxyError::BadResponse));
        }
        return Ok(Response {
            head,
            body: Body::Empty,
            upgrade: Some(Upgrade {
                conn,
                idle: plan.tunnel_idle,
            }),
            local: false,
        });
    }

    conn.requests += 1;
    let body = UpstreamBody {
        conn,
        track: Tracker::new(framing),
        reusable: keep_alive && sent == Sent::All,
    };
    let body = if body.track.ended() {
        body.finish(core);
        Body::Empty
    } else {
        Body::Upstream(body)
    };
    Ok(Response {
        head,
        body,
        upgrade: None,
        local: false,
    })
}

/// How long the origin may take to start its answer before the client is watched: a wait
/// this long is rare, and watching costs the reactor an entry per wait.
const WATCH_CLIENT_AFTER: Duration = Duration::from_secs(1);

/// Reads the origin's final response head into `head`, skipping interim (1xx) responses.
/// The parsed head is cut off the connection's buffer; body bytes that came with it stay.
///
/// `client` is the h1 client's connection and read buffer. Once the origin has been silent
/// for [`WATCH_CLIENT_AFTER`], a client that closes ends the wait, so a hung origin does not
/// hold its connection for a client that left.
async fn read_head(
    conn: &mut UpstreamConn,
    limits: &Limits,
    method: Method,
    timeout: Option<Duration>,
    mut client: Option<(&mut Transport, &mut BytesMut)>,
    head: &mut ResponseHead,
) -> Result<(codec::Framing, bool), ProxyError> {
    let UpstreamConn { io, buf, watch, .. } = conn;
    let now = tokio::time::Instant::now();
    let limit = timeout.map(|t| now + t);
    let watch_client = client.as_ref().map(|_| now + WATCH_CLIENT_AFTER);
    let mut watching = false;
    watch.set_at(match (limit, watch_client) {
        (Some(limit), Some(soon)) => Some(limit.min(soon)),
        (limit, soon) => limit.or(soon),
    });
    loop {
        if !buf.is_empty() {
            match codec::parse_response(buf, limits, method, head) {
                Ok(Parsed::Complete {
                    head_len,
                    framing,
                    extra,
                }) => {
                    buf.advance(head_len);
                    let interim =
                        head.status.code() < 200 && head.status != Status::SWITCHING_PROTOCOLS;
                    if interim {
                        continue;
                    }
                    return Ok((framing, extra.keep_alive));
                }
                Ok(Parsed::Partial) => {}
                Err(_) => return Err(ProxyError::BadResponse),
            }
        }
        let wait = async {
            let read = io.read(buf);
            tokio::pin!(read);
            let gone = async {
                match &mut client {
                    Some((client, kept)) if watching => relay::closed(client, kept).await,
                    _ => std::future::pending().await,
                }
            };
            tokio::pin!(gone);
            poll_fn(|cx| {
                if let Poll::Ready(read) = read.as_mut().poll(cx) {
                    return Poll::Ready(Wait::Read(read));
                }
                if gone.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Wait::ClientGone);
                }
                watch.poll_expired(cx).map(|()| Wait::Expired)
            })
            .await
        };
        match wait.await {
            Wait::Read(Ok(0)) => {
                return Err(ProxyError::Upstream(io::ErrorKind::UnexpectedEof.into()));
            }
            Wait::Read(Ok(_)) => {}
            Wait::Read(Err(e)) => return Err(ProxyError::Upstream(e)),
            Wait::ClientGone => return Err(ProxyError::ClientGone),
            Wait::Expired if limit.is_some_and(|l| tokio::time::Instant::now() >= l) => {
                return Err(ProxyError::ResponseHeaderTimeout);
            }
            Wait::Expired => {
                watching = true;
                watch.set_at(limit);
            }
        }
    }
}

/// How a wait for the origin's response head ended.
enum Wait {
    Read(io::Result<usize>),
    ClientGone,
    Expired,
}

/// A request body that arrives as data chunks (h2, h3), sent with a length when the client
/// declared one and chunked otherwise. The error is the client's.
async fn send_chunks(
    mut head: &[u8],
    body: &mut RequestBody<'_>,
    conn: &mut UpstreamConn,
) -> io::Result<Sent> {
    let chunked = body.len().is_none();
    let mut size = [0u8; 18];
    loop {
        let chunk = body.next_chunk().await?;
        let data = chunk.as_deref().unwrap_or_default();
        let mut slices = relay::framed(head, data, chunked, chunk.is_none(), &mut size);
        if conn.io.write_all_vectored(&mut slices).await.is_err() {
            return Ok(Sent::Interrupted);
        }
        head = &[];
        if chunk.is_none() {
            return Ok(Sent::All);
        }
    }
}

/// `replayable`: nothing of the response had arrived, so the request may be sent again.
struct Failed {
    error: ProxyError,
    replayable: bool,
}

impl UpstreamConn {
    /// Closes a connection whose exchange failed, giving its buffer back.
    fn fail(mut self, core: &Core, error: ProxyError) -> Failed {
        let replayable = self.buf.is_empty() && matches!(error, ProxyError::Upstream(_));
        core.bufs.put(std::mem::take(&mut self.buf));
        Failed { error, replayable }
    }
}

/// An HTTP/1.1 GET with `Connection: upgrade` and an Upgrade field.
fn wants_upgrade(ex: &Exchange) -> bool {
    let fields = &ex.req.fields;
    ex.conn.proto == Proto::H1
        && ex.req.version == Version::Http11
        && ex.req.method == Method::Get
        && fields.get(Known::Upgrade).is_some_and(|v| !v.is_empty())
        && fields.has_token(Known::Connection, b"upgrade")
}

/// Framing of the request body as sent upstream: an h1 body keeps the client's framing (a
/// chunked body passes through with its chunk syntax), a body that arrives as data chunks is
/// chunked here unless its length is known.
fn up_framing(body: &RequestBody<'_>) -> OutFraming {
    match body {
        RequestBody::Empty => OutFraming::None,
        RequestBody::H1(body) => match body.state.track.framing() {
            codec::Framing::Length(n) => OutFraming::Length(n),
            codec::Framing::Chunked => OutFraming::ChunkedPassthrough,
            codec::Framing::None | codec::Framing::UntilClose => OutFraming::None,
        },
        body => body.len().map_or(OutFraming::Chunked, OutFraming::Length),
    }
}

/// Dials an origin within `timeout`: resolve (core cache, `getaddrinfo` on the blocking pool
/// on a miss), TCP connect with TCP_NODELAY, TLS handshake when `up.tls` (sessions resume
/// through the client config's cache).
pub(crate) async fn dial(
    core: &Core,
    up: &UpstreamPlan,
    generation: u64,
    timeout: Duration,
) -> Result<UpstreamConn, ProxyError> {
    let io = tokio::time::timeout(timeout, connect(core, up, generation))
        .await
        .map_err(|_| ProxyError::DialTimeout)??;
    Ok(UpstreamConn {
        io,
        buf: BytesMut::new(),
        upstream: up.id,
        generation,
        idle_since: Instant::now(),
        requests: 0,
        watch: Deadline::default(),
    })
}

async fn connect(
    core: &Core,
    up: &UpstreamPlan,
    generation: u64,
) -> Result<UpstreamIo, ProxyError> {
    let (sock, addr) = match up.addr {
        OriginAddr::Ip(addr) => (Socket::connect(addr).await.map_err(ProxyError::Dial)?, addr),
        OriginAddr::Name => connect_named(core, up, generation).await?,
    };
    let Some(tls) = &up.tls else {
        return Ok(UpstreamIo::Plain(Transport::Plain(sock)));
    };
    let name = match &tls.server_name {
        Some(name) => ServerName::try_from(name.to_string())
            .map_err(|e| ProxyError::Tls(io::Error::other(e)))?,
        None => ServerName::IpAddress(addr.ip().into()),
    };
    let config = core.upstreams.client_tls(tls.verify);
    let stream = tls::ClientStream::connect(sock, config, name)
        .await
        .map_err(ProxyError::Tls)?;
    Ok(UpstreamIo::Tls(Box::new(stream)))
}

/// Connects to the first address of the origin's name that takes the connection, and keeps
/// that address first for the next dial.
async fn connect_named(
    core: &Core,
    up: &UpstreamPlan,
    generation: u64,
) -> Result<(Socket, SocketAddr), ProxyError> {
    let addrs = match core.upstreams.resolved(up, generation) {
        Some(addrs) => addrs,
        None => {
            let target = (up.host.to_string(), up.port);
            let resolved =
                tokio::task::spawn_blocking(move || target.to_socket_addrs().map(Vec::from_iter))
                    .await
                    .map_err(|e| ProxyError::Dial(io::Error::other(e)))?
                    .map_err(ProxyError::Dial)?;
            SmallVec::from_vec(resolved)
        }
    };
    let mut last = io::Error::from(io::ErrorKind::NotFound);
    for (i, &addr) in addrs.iter().enumerate() {
        match Socket::connect(addr).await {
            Ok(sock) => {
                let mut addrs = addrs.clone();
                addrs.swap(0, i);
                core.upstreams.remember(up, generation, Some(addrs));
                return Ok((sock, addr));
            }
            Err(e) => last = e,
        }
    }
    core.upstreams.remember(up, generation, None);
    Err(ProxyError::Dial(last))
}

#[cfg(test)]
mod tests {
    use crate::runtime::testing::{connect, free_addr, plan_from, read_response, served};
    use crate::runtime::{Generation, allowed_cpus, spawn_workers, stop};
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::Instant;

    /// An origin that answers every request head on a connection with `response`.
    fn origin(response: &'static [u8]) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut pending = Vec::new();
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                        while let Some(end) = memchr::memmem::find(&pending, b"\r\n\r\n") {
                            pending.drain(..end + 4);
                            if stream.write_all(response).is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    fn proxied(origin: SocketAddr, listen: SocketAddr) -> Arc<Generation> {
        let plan = plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [listen], "https": [] },
                "sites": [{
                    "name": "proxied",
                    "hosts": ["*"],
                    "headers": { "X-Frame-Options": "DENY", "Server": null },
                    "routes": [{ "proxy": {
                        "to": format!("http://{origin}"),
                        "headers": { "X-Real-IP": "{remote_host}" },
                        "timeouts": { "responseHeader": "15s" },
                    } }],
                }],
            }),
        );
        Arc::new(Generation {
            plan: Arc::new(plan),
            tls: None,
        })
    }

    const REQUEST: &[u8] = b"GET /api/items?limit=20 HTTP/1.1\r\n\
        Host: app.example.com\r\n\
        User-Agent: Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/131.0\r\n\
        Accept: application/json\r\n\
        Accept-Encoding: gzip, br\r\n\
        Cookie: session=0123456789abcdef; theme=dark\r\n\
        CF-Connecting-IP: 203.0.113.7\r\n\
        X-Forwarded-For: 203.0.113.7\r\n\
        \r\n";

    #[test]
    fn zero_allocations_per_proxied_request_after_warm_up() {
        const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\n\
            Content-Type: application/json\r\n\
            Content-Length: 27\r\n\
            Cache-Control: no-store\r\n\
            Server: origin\r\n\
            \r\n\
            {\"items\":[1,2,3],\"next\":4}\n";
        let listen = free_addr();
        let generation = proxied(origin(RESPONSE), listen);
        let workers = spawn_workers(&[allowed_cpus()[0]], generation).unwrap();
        let mut conn = connect(listen);
        let mut request = || {
            conn.write_all(REQUEST).unwrap();
            let (head, body) = read_response(&mut conn).unwrap();
            assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
            assert!(head.contains("\r\nx-frame-options: DENY\r\n"), "{head}");
            assert!(!head.contains("server:"), "{head}");
            assert_eq!(body, b"{\"items\":[1,2,3],\"next\":4}\n");
        };
        for _ in 0..2_000 {
            request();
        }
        let before = served(listen.port(), 0).allocations;
        let requests = 20_000;
        for _ in 0..requests {
            request();
        }
        let after = served(listen.port(), 0).allocations;
        stop(workers, Instant::now());
        println!(
            "core thread allocations over {requests} proxied keep-alive requests: {}",
            after - before
        );
        assert_eq!(after - before, 0, "allocations on the core thread");
    }
}
