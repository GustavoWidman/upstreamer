//! HTTP/2 downstream via the `h2` crate (TLS with ALPN h2 only; no h2c). One local task drives
//! the connection; each stream runs `pipeline::handle` in its own local task (`spawn_local`,
//! `!Send` is fine). Responses stream as DATA frames, honouring flow control; nothing is
//! buffered whole.
//!
//! Writes: the `h2` codec flushes after every DATA frame over 256 bytes, which it hands to the
//! writer by reference. It writes through [`Batched`], where a flush only queues; the driver
//! flushes once the connection has nothing left to do, so the frames of every stream that
//! answered since the last write leave in one write (and, over TLS, in records sealed back to
//! back in one buffer).
//!
//! SETTINGS: initial stream window 1 MiB, connection window 4 MiB (1 MiB bodies in one RTT),
//! max concurrent streams from the config, max header list 64 KiB. Extended CONNECT is not
//! advertised, so browsers open WebSockets over HTTP/1.1, the only upgrade path.
//!
//! A RST_STREAM from the client drops the stream's work where it stands: an upstream exchange
//! in progress is closed, never pooled. Draining sends GOAWAY and lets open streams finish
//! within the shutdown deadline; a connection without streams for `keep_alive` closes the same way.
//!
//! # Allocations per stream
//!
//! The exchange comes from the core's pool, as on h1. What remains is the `spawn_local` task,
//! the `h2` crate's request (`http::Request`, its `HeaderMap` and one `Bytes` per field value
//! the HPACK decoder produced), and the response's `HeaderMap`, where each value is a copied
//! `HeaderValue`. The lib test `allocations_per_stream` measures the total.

use crate::access;
use crate::body::{Body, RequestBody};
use crate::exchange::ConnInfo;
use crate::log::debug;
use crate::msg::{Known, Method, ResponseHead, Status};
use crate::net::Transport;
use crate::pipeline::{self, Response};
use crate::runtime::Core;
use ::h2::server::SendResponse;
use ::h2::{Reason, RecvStream, SendStream};
use bytes::Bytes;
use std::cell::{Cell, RefCell};
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// SETTINGS_INITIAL_WINDOW_SIZE: a 1 MiB request body arrives without a WINDOW_UPDATE wait.
const STREAM_WINDOW: u32 = 1 << 20;
/// The connection window, shared by every stream's request body.
const CONNECTION_WINDOW: u32 = 4 << 20;
/// SETTINGS_MAX_HEADER_LIST_SIZE: decoded names and values plus 32 bytes per field.
const MAX_HEADER_LIST: u32 = 64 * 1024;

/// Serves one connection until the client closes it, a connection error, the idle timeout
/// or the end of a drain.
pub(crate) async fn serve(core: Rc<Core>, io: Transport, info: ConnInfo) {
    let (handshake_timeout, idle_timeout, max_streams) = {
        let server = &core.snapshot().plan.server;
        (server.header_timeout, server.keep_alive, server.max_streams)
    };
    let io = Rc::new(RefCell::new(io));
    let handshake = ::h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(max_streams)
        .max_header_list_size(MAX_HEADER_LIST)
        .handshake::<_, Bytes>(Batched(io.clone()));
    let mut conn = match tokio::time::timeout(handshake_timeout, flushing(&io, handshake)).await {
        Ok(Ok(Ok(conn))) => conn,
        Ok(Ok(Err(e))) => {
            debug!(
                "core {}: h2 handshake from {}: {e}",
                core.index, info.remote
            );
            return;
        }
        Ok(Err(e)) => {
            debug!("core {}: h2 write to {}: {e}", core.index, info.remote);
            return;
        }
        Err(_) => return,
    };

    let open = Rc::new(Open {
        streams: Cell::new(0),
        idle_since: Cell::new(Instant::now()),
    });
    let mut drain = pin!(core.until_drain());
    let mut idle = pin!(tokio::time::sleep(idle_timeout));
    // Set once GOAWAY is on its way: from then on only the connection's own end matters.
    let mut closing = false;
    loop {
        let event = poll_fn(|cx| {
            if let Poll::Ready(accepted) = conn.poll_accept(cx) {
                return Poll::Ready(Event::Accepted(accepted));
            }
            if !closing && drain.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Event::Drain);
            }
            if !closing && idle.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Event::IdleCheck);
            }
            Poll::Pending
        });
        let event = match flushing(&io, event).await {
            Ok(event) => event,
            Err(e) => {
                debug!("core {}: h2 write to {}: {e}", core.index, info.remote);
                break;
            }
        };
        match event {
            Event::Accepted(Some(Ok((req, respond)))) => {
                let guard = Open::enter(&open);
                // Boxed, the task's moves of the stream's state (spawning, completing) copy a
                // pointer instead of the state.
                let work = Box::pin(stream(core.clone(), info, req, respond, guard));
                tokio::task::spawn_local(work);
            }
            Event::Accepted(Some(Err(e))) => {
                debug!("core {}: h2 from {}: {e}", core.index, info.remote);
                break;
            }
            Event::Accepted(None) => break,
            Event::Drain => {
                closing = true;
                conn.graceful_shutdown();
            }
            Event::IdleCheck => {
                let since = open.idle_since.get();
                if open.streams.get() == 0 && since.elapsed() >= idle_timeout {
                    closing = true;
                    conn.graceful_shutdown();
                } else {
                    let from = if open.streams.get() == 0 {
                        since
                    } else {
                        Instant::now()
                    };
                    idle.as_mut().reset(from + idle_timeout);
                }
            }
        }
    }
}

enum Event<T> {
    Accepted(Option<Result<T, ::h2::Error>>),
    Drain,
    IdleCheck,
}

/// Runs `work`, writing what the codec queued whenever `work` waits.
async fn flushing<T>(io: &RefCell<Transport>, work: impl Future<Output = T>) -> io::Result<T> {
    let mut work = pin!(work);
    poll_fn(|cx| {
        if let Poll::Ready(out) = work.as_mut().poll(cx) {
            return Poll::Ready(Ok(out));
        }
        match Pin::new(&mut *io.borrow_mut()).poll_flush(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Pending,
        }
    })
    .await
}

/// The connection's transport as the `h2` codec sees it: shared with the driver, which owns
/// the flushes (see the module docs). Borrowed only inside a poll, never across one.
struct Batched(Rc<RefCell<Transport>>);

impl AsyncRead for Batched {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.borrow_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for Batched {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.borrow_mut()).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0.borrow_mut()).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0.borrow_mut()).poll_shutdown(cx)
    }
}

/// The streams a connection has in progress, and since when it has had none.
struct Open {
    streams: Cell<usize>,
    idle_since: Cell<Instant>,
}

impl Open {
    fn enter(open: &Rc<Open>) -> StreamGuard {
        open.streams.set(open.streams.get() + 1);
        StreamGuard(open.clone())
    }
}

/// Counts one stream as open until it drops.
struct StreamGuard(Rc<Open>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let left = self.0.streams.get() - 1;
        self.0.streams.set(left);
        if left == 0 {
            self.0.idle_since.set(Instant::now());
        }
    }
}

/// One stream: head conversion (one copy of the header block into the exchange), the
/// pipeline, then DATA frames from `Body::next_chunk`.
async fn stream(
    core: Rc<Core>,
    info: ConnInfo,
    req: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    _open: StreamGuard,
) {
    // Once per request, as on h1: a reload applies to the next stream.
    let snap = core.snapshot();
    let mut ex = core.exchanges.take(info, snap.plan.var_count);
    let (parts, recv) = req.into_parts();
    let (resp, log) = match admit(&parts, snap.plan.server.max_header_fields) {
        Err(status) => (pipeline::bare(&mut ex, status), None),
        Ok(()) if ex.req.fill_from_http(&parts).is_err() => {
            (pipeline::bare(&mut ex, Status::BAD_REQUEST), None)
        }
        Ok(()) => {
            let body = request_body(&parts.headers, recv);
            let handled = {
                let handled = pin!(pipeline::handle(&core, &snap, &mut ex, body));
                or_reset(handled, |cx| respond.poll_reset(cx)).await
            };
            match handled {
                Some(resp) => resp,
                None => {
                    core.exchanges.put(ex);
                    return;
                }
            }
        }
    };
    #[cfg(test)]
    crate::runtime::testing::observe(&core, &info);

    let Response {
        head, body, local, ..
    } = resp;
    let status = head.status;
    let head_only = ex.req.method == Method::Head || !head.status.has_body();
    let length = if head_only {
        head_only_length(local, &head, &body)
    } else {
        body.len()
    };
    let mut out = head.to_http();
    let fields = out.headers_mut();
    if let Some(length) = length {
        fields.insert(http::header::CONTENT_LENGTH, length.into());
    }
    if local {
        let date = core.clock.http_date.borrow();
        if let Ok(date) = http::HeaderValue::from_bytes(&date[..]) {
            fields.insert(http::header::DATE, date);
        }
    }
    ex.recycle(head);

    let empty = head_only || length == Some(0);
    let mut sent = 0;
    match respond.send_response(out, empty) {
        Ok(send) if !empty => send_body(&core, body, send, &mut sent).await,
        Ok(_) => discard(&core, body),
        Err(e) => debug!("core {}: h2 response to {}: {e}", core.index, info.remote),
    }
    if let Some(log) = log {
        access::record(&core, &snap, &ex, log, status, sent);
    }
    core.exchanges.put(ex);
}

/// Requests the pipeline never sees: more fields than the config allows (h1 has the same
/// limit), answered 431.
fn admit(parts: &http::request::Parts, max_fields: u16) -> Result<(), Status> {
    if parts.headers.len() > usize::from(max_fields) {
        return Err(Status::HEADER_FIELDS_TOO_LARGE);
    }
    Ok(())
}

/// The request body: none when HEADERS ended the stream, else the stream's DATA with the
/// length the client declared. The `h2` crate resets a stream whose DATA does not add up to
/// its content-length, so the length can frame the upstream request.
fn request_body(fields: &http::HeaderMap, recv: RecvStream) -> RequestBody<'static> {
    if recv.is_end_stream() {
        return RequestBody::Empty;
    }
    let len = fields
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse().ok());
    RequestBody::H2(H2Body { recv, len })
}

/// The content-length of a response sent without a body: what the body would have been for
/// HEAD, nothing for 1xx and 204, and for 304 only what the origin declared (a local 304 has
/// no representation at hand to measure).
fn head_only_length(local: bool, head: &ResponseHead, body: &Body) -> Option<u64> {
    let status = head.status;
    if status.code() < 200 || status == Status::NO_CONTENT {
        return None;
    }
    if !local {
        return head
            .fields
            .get(Known::ContentLength)
            .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok());
    }
    if status == Status::NOT_MODIFIED {
        return None;
    }
    body.len()
}

/// Runs `work` until it finishes, or drops it when the client resets the stream or the
/// connection fails (`None`). The caller pins `work`, so the stream's future holds it once.
async fn or_reset<T>(
    mut work: Pin<&mut impl Future<Output = T>>,
    mut reset: impl FnMut(&mut Context<'_>) -> Poll<Result<Reason, ::h2::Error>>,
) -> Option<T> {
    poll_fn(|cx| {
        if let Poll::Ready(out) = work.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        reset(cx).map(|_| None)
    })
    .await
}

/// Sends a response body as DATA frames, waiting for window capacity per chunk. The next
/// chunk is read only once the previous one is in the stream's window, so an event stream's
/// events go out as they arrive and a slow client slows the origin down. `sent` counts the
/// bytes handed to the stream.
async fn send_body(core: &Core, mut body: Body, mut send: SendStream<Bytes>, sent: &mut u64) {
    loop {
        let next = or_reset(pin!(body.next_chunk(core)), |cx| send.poll_reset(cx)).await;
        let chunk = match next {
            None => return,
            Some(Ok(Some(chunk))) => chunk,
            Some(Ok(None)) => {
                let _ = send.send_data(Bytes::new(), true);
                return;
            }
            Some(Err(e)) => {
                debug!("core {}: h2 response body: {e}", core.index);
                send.send_reset(Reason::INTERNAL_ERROR);
                return;
            }
        };
        // A body of known length ends with its last byte, in the frame that carries it.
        let last = body.len() == Some(0);
        let len = chunk.len() as u64;
        if send_data(&mut send, chunk, last).await.is_err() {
            return;
        }
        *sent += len;
        if last {
            discard(core, body);
            return;
        }
    }
}

/// Sends `data` in frames no larger than the capacity the peer's windows grant.
async fn send_data(
    send: &mut SendStream<Bytes>,
    mut data: Bytes,
    end: bool,
) -> Result<(), ::h2::Error> {
    send.reserve_capacity(data.len());
    while !data.is_empty() {
        let mut granted = send.capacity();
        if granted == 0 {
            granted = match poll_fn(|cx| send.poll_capacity(cx)).await {
                Some(granted) => granted?,
                None => return Err(Reason::STREAM_CLOSED.into()),
            };
        }
        let piece = data.split_to(granted.min(data.len()));
        send.send_data(piece, end && data.is_empty())?;
    }
    Ok(())
}

/// Ends a body that will not be sent: an upstream connection goes back to its pool when the
/// body was complete.
fn discard(core: &Core, body: Body) {
    if let Body::Upstream(upstream) = body {
        upstream.finish(core);
    }
}

/// The receive half of an h2 request stream, as a request body.
pub(crate) struct H2Body {
    recv: RecvStream,
    /// The client's content-length.
    len: Option<u64>,
}

impl H2Body {
    pub fn len(&self) -> Option<u64> {
        self.len
    }

    /// The next DATA payload; `None` at the end of the stream. Each payload's bytes go back
    /// to the client's windows as soon as they are handed on, so the windows bound what is
    /// buffered for a request.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            match self.recv.data().await {
                None => return Ok(None),
                Some(Ok(data)) => {
                    let _ = self.recv.flow_control().release_capacity(data.len());
                    if !data.is_empty() {
                        return Ok(Some(data));
                    }
                }
                Some(Err(e)) => return Err(io::Error::other(e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::net::Socket;
    use crate::proxy::tls::ClientStream;
    use crate::runtime::testing::{free_addr, plan_from, served};
    use crate::runtime::{Generation, TlsState, allowed_cpus, spawn_workers, stop};
    use crate::tls::{self, TicketKeys};
    use bytes::Bytes;
    use std::sync::Arc;
    use std::time::Instant;

    /// One core with an HTTPS listener whose site answers every request with `hi`.
    fn generation(addr: std::net::SocketAddr) -> Arc<Generation> {
        let plan = plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": [], "https": [addr] },
                "sites": [{
                    "name": "test",
                    "hosts": ["test.example"],
                    "tls": {
                        "cert": "/nonexistent/fullchain.pem",
                        "key": "/nonexistent/key.pem",
                        "redirectHttp": false,
                        "http3": false,
                    },
                    "routes": [{ "respond": { "body": "hi" } }],
                }],
            }),
        );
        let (certs, _) = tls::load(&plan.certs, None);
        Arc::new(Generation {
            plan: Arc::new(plan),
            tls: Some(TlsState {
                certs: Arc::new(certs),
                tickets: Arc::new(TicketKeys::generate(3600)),
            }),
            access: Arc::default(),
        })
    }

    async fn client(addr: std::net::SocketAddr) -> ::h2::client::SendRequest<Bytes> {
        let mut config = (*tls::client_config(false)).clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let sock = Socket::connect(addr).await.unwrap();
        let name = "test.example".try_into().unwrap();
        let io = ClientStream::connect(sock, Arc::new(config), name)
            .await
            .unwrap();
        let (send, conn) = ::h2::client::handshake(io).await.unwrap();
        tokio::spawn(conn);
        send
    }

    /// Fields a browser sends with a navigation.
    const BROWSER: &[(&str, &str)] = &[
        (
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("accept-language", "en-US,en;q=0.5"),
        ("accept-encoding", "gzip, deflate, br, zstd"),
        ("cookie", "session=0123456789abcdef; theme=dark"),
        ("cookie", "lang=en"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-site", "none"),
        ("sec-fetch-user", "?1"),
        ("upgrade-insecure-requests", "1"),
        ("priority", "u=0, i"),
    ];

    async fn get(send: &mut ::h2::client::SendRequest<Bytes>, fields: &[(&str, &str)]) {
        std::future::poll_fn(|cx| send.poll_ready(cx))
            .await
            .unwrap();
        let mut req = http::Request::get("https://test.example/");
        for (name, value) in fields {
            req = req.header(*name, *value);
        }
        let req = req.body(()).unwrap();
        let (response, _) = send.send_request(req, true).unwrap();
        let mut body = response.await.unwrap().into_body();
        let mut got = Vec::new();
        while let Some(data) = body.data().await {
            got.extend_from_slice(&data.unwrap());
        }
        assert_eq!(got, b"hi");
    }

    /// Allocations the core thread makes per stream on a warm keep-alive connection: the
    /// `h2` crate's request and response objects and the stream task (see the module docs).
    #[test]
    fn allocations_per_stream() {
        let addr = free_addr();
        let workers = spawn_workers(&[allowed_cpus()[0]], generation(addr)).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let streams = 10_000;
        let measured = runtime.block_on(async {
            let mut send = client(addr).await;
            let mut measured = Vec::new();
            for fields in [&[][..], BROWSER] {
                for _ in 0..2_000 {
                    get(&mut send, fields).await;
                }
                let before = served(addr.port(), 0).allocations;
                for _ in 0..streams {
                    get(&mut send, fields).await;
                }
                let after = served(addr.port(), 0).allocations;
                measured.push((after - before) as f64 / f64::from(streams));
            }
            measured
        });
        stop(workers, Instant::now());
        let [bare, browser] = measured[..] else {
            unreachable!()
        };
        println!(
            "core thread allocations per h2 stream: {bare:.2} without fields, \
             {browser:.2} with a browser's {} fields",
            BROWSER.len()
        );
        assert!(bare <= 16.0, "{bare} allocations per stream");
        assert!(browser <= 32.0, "{browser} allocations per stream");
    }
}
