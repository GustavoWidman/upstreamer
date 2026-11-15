//! HTTP/3 downstream via `quinn` + `h3`. Each core runs one quinn endpoint per QUIC listener on
//! its own SO_REUSEPORT UDP socket (GSO/GRO through quinn-udp); `runtime` accepts on it and
//! hands every incoming connection to [`serve`]. The kernel's 4-tuple hash keeps a connection's
//! packets on one core as long as the client does not migrate.
//!
//! Same pipeline as h1/h2: each request stream converts its head into an exchange (one copy of
//! the header block), runs `pipeline::handle`, and sends the response body as DATA frames, one
//! chunk read per chunk written, under QUIC flow control. Request bodies stream to the origin
//! the same way.
//!
//! Drain: a connection sends GOAWAY, lets its open streams finish and their last bytes
//! arrive, then closes with H3_NO_ERROR. Reload swaps the endpoint's server config, so the
//! socket and every open connection stay.

use crate::access;
use crate::body::{Body, RequestBody};
use crate::exchange::{ConnInfo, Exchange, Proto, Scheme};
use crate::log::debug;
use crate::msg::{Known, Method, ResponseHead, Status};
use crate::pipeline::{self, Response};
use crate::plan::{ListenerKey, ServerParams};
use crate::runtime::Core;
use bytes::{Buf, Bytes};
use h3::error::Code;
use std::cell::Cell;
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::Notify;

type Connection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type SendStream = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RecvStream = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

/// QUIC transport settings for the plan's limits: `maxStreams` bounds the request streams a
/// client may have open at once and `keepAlive` is how long a connection without traffic stays
/// open.
pub(crate) fn transport(server: &ServerParams) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(server.max_streams.into())
        .max_idle_timeout(quinn::IdleTimeout::try_from(server.keep_alive).ok());
    Arc::new(transport)
}

/// Serves one QUIC connection from handshake to close.
pub(crate) async fn serve(core: Rc<Core>, incoming: quinn::Incoming, listener: ListenerKey) {
    let server = core.snapshot().plan.server.clone();
    let info = ConnInfo {
        remote: incoming.remote_address(),
        local_port: listener.addr.port(),
        scheme: Scheme::Https,
        proto: Proto::H3,
        listener,
    };
    let start = async {
        let quic = incoming.await.map_err(|e| e.to_string())?;
        let conn = h3::server::builder()
            .max_field_section_size(server.max_head_bytes.into())
            .build(h3_quinn::Connection::new(quic.clone()))
            .await
            .map_err(|e| e.to_string())?;
        Ok::<_, String>((quic, conn))
    };
    let (quic, mut conn) = match tokio::time::timeout(server.header_timeout, start).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(e)) => return debug!("core {}: QUIC from {}: {e}", core.index, info.remote),
        Err(_) => {
            return debug!(
                "core {}: QUIC from {}: handshake timeout",
                core.index, info.remote
            );
        }
    };
    let streams = Rc::new(Streams::default());
    accept(&core, &quic, &mut conn, info, &streams).await;
}

/// Accepts request streams until the client or the idle timeout ends the connection, or until
/// a drain's GOAWAY has let the last open stream finish and its bytes arrive. Dropping the
/// connection afterwards closes it with H3_NO_ERROR.
async fn accept(
    core: &Rc<Core>,
    quic: &quinn::Connection,
    conn: &mut Connection,
    info: ConnInfo,
    streams: &Rc<Streams>,
) {
    let drain = core.until_drain();
    tokio::pin!(drain);
    let mut draining = false;
    loop {
        tokio::select! {
            accepted = conn.accept() => match accepted {
                Ok(Some(resolver)) if draining => {
                    tokio::task::spawn_local(reject(resolver));
                }
                Ok(Some(resolver)) => {
                    let open = streams.open();
                    tokio::task::spawn_local(stream(core.clone(), info, resolver, open));
                }
                Ok(None) => return,
                Err(e) => {
                    if !e.is_h3_no_error() {
                        debug!("core {}: h3 from {}: {e}", core.index, info.remote);
                    }
                    return;
                }
            },
            () = &mut drain, if !draining => {
                draining = true;
                streams.draining.set(true);
                // h3 sends the stream id it computes here as GOAWAY's and still accepts that
                // stream. One past the last accepted stream is the id RFC 9114 section 5.2 asks
                // for (every lower one is processed), and the arm above rejects the stream
                // h3 lets through.
                if conn.shutdown(1).await.is_err() {
                    return;
                }
            }
            () = async { streams.finished().await; delivered(quic).await }, if draining => return,
        }
    }
}

/// A request stream at or past the GOAWAY id: not processed, so the client may retry it on a
/// new connection.
async fn reject(resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>) {
    if let Ok((_, mut stream)) = resolver.resolve_request().await {
        stream.stop_sending(Code::H3_REQUEST_REJECTED);
        stream.stop_stream(Code::H3_REQUEST_REJECTED);
    }
}

/// Resolves once the connection has sent no stream data and no probe for a quiet window,
/// which is how long the client's acknowledgement of the last packet can take. Closing a
/// connection discards whatever response bytes are not acknowledged yet, and h3-quinn does
/// not expose quinn's per-stream acknowledgement (`SendStream::stopped`).
async fn delivered(quic: &quinn::Connection) {
    let sent = || {
        let frames = quic.stats().frame_tx;
        frames.stream + frames.ping
    };
    let mut before = sent();
    loop {
        tokio::time::sleep(quic.rtt() * 3 + QUIET_SLACK).await;
        let now = sent();
        if now == before {
            return;
        }
        before = now;
    }
}

/// Added to three round trips in [`delivered`]: the client's acknowledgement delay (25 ms by
/// default, RFC 9000 section 18.2) twice, plus timer slack.
const QUIET_SLACK: std::time::Duration = std::time::Duration::from_millis(60);

/// The request streams of one connection that are still running.
#[derive(Default)]
struct Streams {
    open: Cell<usize>,
    /// Only a draining connection waits for its streams, so only then does the last stream
    /// to end wake it (the signal takes a lock).
    draining: Cell<bool>,
    none_open: Notify,
}

impl Streams {
    fn open(self: &Rc<Self>) -> OpenStream {
        self.open.set(self.open.get() + 1);
        OpenStream(self.clone())
    }
    /// Resolves once no stream is open.
    async fn finished(&self) {
        while self.open.get() > 0 {
            self.none_open.notified().await;
        }
    }
}

/// Counts a stream as open until dropped.
struct OpenStream(Rc<Streams>);

impl Drop for OpenStream {
    fn drop(&mut self) {
        let left = self.0.open.get() - 1;
        self.0.open.set(left);
        if left == 0 && self.0.draining.get() {
            self.0.none_open.notify_one();
        }
    }
}

/// One request: head conversion, the pipeline, the response.
async fn stream(
    core: Rc<Core>,
    info: ConnInfo,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    _open: OpenStream,
) {
    let (request, stream) = match resolver.resolve_request().await {
        Ok(resolved) => resolved,
        Err(e) => return debug!("core {}: h3 request from {}: {e}", core.index, info.remote),
    };
    let (mut send, mut recv) = stream.split();
    let (parts, ()) = request.into_parts();
    // Once per request, as on h1: a reload applies to the next request of every connection.
    let snap = core.snapshot();
    let mut ex = core.exchanges.take(info, snap.plan.var_count);
    let (resp, log) = match head(&mut ex, &parts, &snap.plan.server) {
        Err(status) => {
            recv.stop_sending(Code::H3_NO_ERROR);
            (pipeline::bare(&mut ex, status), None)
        }
        Ok(declared) => match request_body(recv, declared).await {
            Ok(body) => pipeline::handle(&core, &snap, &mut ex, body).await,
            Err(BodyError::Malformed) => (pipeline::bare(&mut ex, Status::BAD_REQUEST), None),
            Err(BodyError::Gone) => {
                core.exchanges.put(ex);
                return;
            }
        },
    };
    #[cfg(test)]
    crate::runtime::testing::observe(&core, &info);
    let status = resp.head.status;
    let mut sent = 0;
    if let Err(e) = respond(&core, &mut send, &mut ex, resp, &mut sent).await {
        debug!("core {}: h3 response to {}: {e}", core.index, info.remote);
        send.stop_stream(Code::H3_INTERNAL_ERROR);
    }
    if let Some(log) = log {
        access::record(&core, &snap, &ex, log, status, sent);
    }
    core.exchanges.put(ex);
}

/// Fills the exchange's request head from the h3 head. Returns the declared Content-Length,
/// or the status that answers a head the pipeline must not see.
fn head(
    ex: &mut Exchange,
    parts: &http::request::Parts,
    server: &ServerParams,
) -> Result<Option<u64>, Status> {
    if parts.headers.len() > usize::from(server.max_header_fields) {
        return Err(Status::HEADER_FIELDS_TOO_LARGE);
    }
    ex.req
        .fill_from_http(parts)
        .map_err(|_| Status::BAD_REQUEST)?;
    let mut declared = None;
    for value in parts.headers.get_all(http::header::CONTENT_LENGTH) {
        let n = std::str::from_utf8(value.as_bytes())
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .ok_or(Status::BAD_REQUEST)?;
        if declared.is_some_and(|d| d != n) {
            return Err(Status::BAD_REQUEST);
        }
        declared = Some(n);
    }
    Ok(declared)
}

enum BodyError {
    /// The stream ended before the length the request declared.
    Malformed,
    /// The client reset the stream.
    Gone,
}

/// Waits for the stream's first data or its end, so a request without a body reaches the
/// origin as one (no chunked framing, replayable on a stale pooled connection).
async fn request_body(
    mut recv: RecvStream,
    declared: Option<u64>,
) -> Result<RequestBody<'static>, BodyError> {
    let first = next_data(&mut recv).await.map_err(|_| BodyError::Gone)?;
    match first {
        None if declared.unwrap_or(0) == 0 => Ok(RequestBody::Empty),
        None => Err(BodyError::Malformed),
        Some(first) => Ok(RequestBody::H3(H3Body {
            recv: Box::new(recv),
            first: Some(first),
            declared,
            received: 0,
            ended: false,
        })),
    }
}

/// The next non-empty DATA payload, `None` at the end of the request (trailers are ignored).
async fn next_data(recv: &mut RecvStream) -> Result<Option<Bytes>, h3::error::StreamError> {
    loop {
        match recv.recv_data().await? {
            None => return Ok(None),
            // The payload is a `Bytes` underneath, so this is a split, not a copy.
            Some(mut data) if data.has_remaining() => {
                return Ok(Some(data.copy_to_bytes(data.remaining())));
            }
            Some(_) => {}
        }
    }
}

/// The receive half of an h3 request stream that carries a body.
pub(crate) struct H3Body {
    /// Boxed so a request body stays small while it moves through the pipeline; only requests
    /// that carry a body pay for it.
    recv: Box<RecvStream>,
    /// Read before the pipeline ran, to tell a body from none.
    first: Option<Bytes>,
    /// The request's Content-Length. RFC 9114 section 4.1.2 makes a body of another length
    /// malformed, so the data is checked against it: an origin that was promised `n` bytes
    /// never gets more or fewer.
    pub declared: Option<u64>,
    received: u64,
    ended: bool,
}

impl H3Body {
    /// The next piece of body data; `None` at the end.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        let chunk = match self.first.take() {
            Some(first) => Some(first),
            None if self.ended => None,
            None => next_data(&mut self.recv).await.map_err(io::Error::other)?,
        };
        match chunk {
            Some(chunk) => {
                self.received += chunk.len() as u64;
                if self.declared.is_some_and(|d| self.received > d) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(Some(chunk))
            }
            None => {
                self.ended = true;
                if self.declared.is_some_and(|d| self.received != d) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok(None)
            }
        }
    }
}

impl Drop for H3Body {
    /// A response sent before the whole body was read tells the client to stop sending
    /// (RFC 9114 section 4.1).
    fn drop(&mut self) {
        if !self.ended {
            self.recv.stop_sending(Code::H3_NO_ERROR);
        }
    }
}

/// Sends the response head, then the body chunk by chunk, then the end of the stream. `sent`
/// counts the body bytes handed to the stream.
async fn respond(
    core: &Core,
    send: &mut SendStream,
    ex: &mut Exchange,
    resp: Response,
    sent: &mut u64,
) -> Result<(), String> {
    let Response {
        head,
        mut body,
        upgrade: _,
        local,
    } = resp;
    let head_only = ex.req.method == Method::Head || !head.status.has_body();
    let length = if head_only {
        head_only_length(local, &head, &body)
    } else {
        body.len()
    };
    let mut http = head.to_http();
    ex.recycle(head);
    let fields = http.headers_mut();
    if let Some(n) = length {
        fields.insert(http::header::CONTENT_LENGTH, n.into());
    }
    if local {
        let date = *core.clock.http_date.borrow();
        if let Ok(date) = http::HeaderValue::from_bytes(&date) {
            fields.insert(http::header::DATE, date);
        }
    }
    send.send_response(http).await.map_err(|e| e.to_string())?;
    if head_only {
        if let Body::Upstream(upstream) = body {
            upstream.finish(core);
        }
    } else {
        while let Some(chunk) = body.next_chunk(core).await.map_err(|e| e.to_string())? {
            let len = chunk.len() as u64;
            send.send_data(chunk).await.map_err(|e| e.to_string())?;
            *sent += len;
        }
    }
    send.finish().await.map_err(|e| e.to_string())
}

/// The Content-Length of a response that carries no body (HEAD, 204, 304): the length the
/// body would have. A local body has it; a proxied response keeps what the origin declared.
fn head_only_length(local: bool, head: &ResponseHead, body: &Body) -> Option<u64> {
    if local {
        return body.len();
    }
    head.fields
        .get(Known::ContentLength)
        .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use crate::exchange::{ConnInfo, Exchange, Proto, Scheme};
    use crate::msg::{Known, Status};
    use crate::pipeline;
    use crate::plan::{ListenerKind, Plan};
    use crate::runtime::testing::{plan_from, served};
    use crate::runtime::{Generation, TlsState, allowed_cpus, spawn_workers, stop};
    use crate::tls::{self, TicketKeys};
    use bytes::{Buf, Bytes};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    /// A plan with one TLS site on `addr` (TCP and, with `http3`, UDP) that answers
    /// `hello`, and its certificates: a self-signed one, since the files do not exist.
    fn generation(addr: SocketAddr, http3: bool) -> Arc<Generation> {
        let plan = plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [], "https": [] },
                "sites": [{
                    "name": "h3",
                    "hosts": ["h3.test"],
                    "listen": [addr],
                    "tls": {
                        "cert": "/nonexistent/h3.crt",
                        "key": "/nonexistent/h3.key",
                        "redirectHttp": false,
                        "http3": http3,
                    },
                    "routes": [{ "respond": { "body": "hello" } }],
                }],
            }),
        );
        let certs = Arc::new(tls::load(&plan.certs, None).0);
        Arc::new(Generation {
            plan: Arc::new(plan),
            tls: Some(TlsState {
                certs,
                tickets: Arc::new(TicketKeys::generate(3600)),
            }),
            access: Arc::default(),
        })
    }

    /// A free port for both TCP and UDP on loopback.
    fn free_addr() -> SocketAddr {
        loop {
            let addr = crate::runtime::testing::free_addr();
            if std::net::UdpSocket::bind(addr).is_ok() {
                return addr;
            }
        }
    }

    /// An h3 client connection from a UDP socket of its own.
    struct Client {
        send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
        _endpoint: quinn::Endpoint,
    }

    impl Client {
        async fn connect(addr: SocketAddr) -> Client {
            let mut crypto = (*tls::client_config(false)).clone();
            crypto.alpn_protocols = vec![b"h3".to_vec()];
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
            let quic = endpoint.connect(addr, "h3.test").unwrap().await.unwrap();
            let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(quic))
                .await
                .unwrap();
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
            Client {
                send,
                _endpoint: endpoint,
            }
        }

        async fn get(&mut self) -> (u16, Vec<u8>) {
            let request = http::Request::get("https://h3.test/").body(()).unwrap();
            let mut stream = self.send.send_request(request).await.unwrap();
            stream.finish().await.unwrap();
            let response = stream.recv_response().await.unwrap();
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            (response.status().as_u16(), body)
        }
    }

    fn client_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn connections_spread_over_cores() {
        let cores: Vec<usize> = allowed_cpus().into_iter().take(4).collect();
        let addr = free_addr();
        let workers = spawn_workers(&cores, generation(addr, true)).unwrap();
        let connections = 64;
        client_runtime().block_on(async {
            for _ in 0..connections {
                let mut client = Client::connect(addr).await;
                assert_eq!(client.get().await, (200, b"hello".to_vec()));
            }
        });
        stop(workers, Instant::now());
        let per_core: Vec<u64> = (0..cores.len())
            .map(|core| served(addr.port(), core).requests)
            .collect();
        println!(
            "h3 connections per core over {} cores: {per_core:?}",
            cores.len()
        );
        assert_eq!(per_core.iter().sum::<u64>(), connections);
        if cfg!(target_os = "linux") {
            assert!(
                per_core.iter().all(|&n| n > 0),
                "the kernel spreads QUIC connections over every core: {per_core:?}"
            );
        }
    }

    #[test]
    fn allocations_per_request_on_the_core() {
        let addr = free_addr();
        let workers = spawn_workers(&[allowed_cpus()[0]], generation(addr, true)).unwrap();
        let requests = 2_000;
        let (before, after) = client_runtime().block_on(async {
            let mut client = Client::connect(addr).await;
            for _ in 0..500 {
                client.get().await;
            }
            let before = served(addr.port(), 0).allocations;
            for _ in 0..requests {
                assert_eq!(client.get().await.0, 200);
            }
            (before, served(addr.port(), 0).allocations)
        });
        stop(workers, Instant::now());
        let per_request = (after - before) as f64 / f64::from(requests);
        println!(
            "core thread allocations per h3 request (driver, quinn and h3 included): {per_request:.1}"
        );
        assert!(
            per_request < 200.0,
            "allocations per h3 request: {per_request:.1}"
        );
    }

    fn exchange(plan: &Plan, proto: Proto) -> Exchange {
        let listener = plan
            .listeners
            .iter()
            .find(|l| {
                (l.key.kind == ListenerKind::Quic) == (proto == Proto::H3)
                    && l.key.kind != ListenerKind::Http
            })
            .unwrap()
            .key;
        let conn = ConnInfo {
            remote: "192.0.2.1:5000".parse().unwrap(),
            local_port: listener.addr.port(),
            scheme: Scheme::Https,
            proto,
            listener,
        };
        Exchange::new(conn, plan.var_count)
    }

    #[test]
    fn alt_svc_advertises_h3_on_h1_and_h2_responses_of_http3_sites() {
        let addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        let alt_svc = |http3: bool, proto: Proto| {
            let generation = generation(addr, http3);
            let plan = &generation.plan;
            let mut ex = exchange(plan, proto);
            let mut resp = pipeline::bare(&mut ex, Status::OK);
            pipeline::finalize(&plan.sites[0], &mut ex, &mut resp);
            resp.head.fields.get(Known::AltSvc).map(<[u8]>::to_vec)
        };
        let advertised = Some(br#"h3=":8443"; ma=86400"#.to_vec());
        assert_eq!(alt_svc(true, Proto::H1), advertised, "h1 over TLS");
        assert_eq!(alt_svc(true, Proto::H2), advertised, "h2");
        assert_eq!(alt_svc(true, Proto::H3), None, "not on h3 itself");
        assert_eq!(alt_svc(false, Proto::H1), None, "a site with http3 off");
    }
}
