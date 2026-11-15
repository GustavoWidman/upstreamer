//! HTTP/2 downstream through the `h2` crate: the driver this module's parent replaces, kept
//! selectable while the two are compared. A process started with `UPSTREAMER_H2_CRATE` set
//! serves HTTP/2 with it.
//!
//! One local task drives the connection; each stream runs `pipeline::handle` in its own
//! local task. The `h2` codec writes through [`Batched`], where a flush only queues; the
//! driver flushes once the connection has nothing left to do.

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

/// Whether this process serves HTTP/2 through the `h2` crate.
pub(crate) fn selected() -> bool {
    static SELECTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SELECTED.get_or_init(|| std::env::var_os("UPSTREAMER_H2_CRATE").is_some())
}

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
    RequestBody::H2Legacy(H2Body { recv, len })
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
