//! The HTTP/1.1 connection driver: one local task per connection, which does everything for its
//! requests inline (routing, the upstream exchange, the body relay). No channel, no extra task,
//! no cross-thread wake between accepting a request and answering it.
//!
//! # Keep-alive proxied request, steady state, epoll backend
//!
//! | step | syscalls | allocations |
//! |---|---|---|
//! | wait for the request (idle connection holds no buffer) | epoll_wait, amortised over all ready sockets | 0 |
//! | take read buffer + exchange from the core pools | 0 | 0 |
//! | `read` the request (short read clears readiness, so no EAGAIN read follows) | 1 | 0 |
//! | parse head (httparse), copy head into the exchange's recycled buffer, route | 0 | 0 |
//! | check out a pooled upstream connection (core-local LIFO, no lock) | 0 | 0 |
//! | `writev` request head (+ any body bytes already read) upstream | 1 | 0 |
//! | wait for the upstream (epoll_wait, amortised) | ~0 | 0 |
//! | `read` the response into the upstream connection's buffer | 1 | 0 |
//! | parse response head, finalize headers, serialise into the exchange's `out` | 0 | 0 |
//! | `writev` [head, body bytes still in the upstream buffer] downstream | 1 | 0 |
//! | check the upstream connection back in, return buffers and exchange | 0 | 0 |
//!
//! Four socket syscalls per request, zero heap allocations. The io_uring backend keeps the
//! same driver and removes the per-request syscalls into one batched `io_uring_enter` per
//! loop turn.
//!
//! # Timeouts
//!
//! One [`Deadline`] per connection covers its waits in turn: keep-alive while idle, the
//! header timeout once a request head has started and not finished, the header timeout again
//! while an unread request body is drained. A request whose head arrives in one read never
//! touches the timer wheel.
//!
//! # Where buffers live
//!
//! - Downstream read buffer: core `BufPool` (16 KiB), lent while a request is in progress;
//!   kept across requests only when it holds pipelined bytes.
//! - Request/response heads, arena, `out`: the `Exchange` (core `ExchangePool`).
//! - Upstream read buffer: lent from the core `BufPool` while the upstream connection is
//!   checked out; a connection is pooled only with an empty buffer.
//! - Body relays: in place in whichever read buffer the bytes arrived in; long bodies and
//!   tunnels move to a 64 KiB pool buffer (sendfile for files on kernel-plaintext sockets).

use crate::access;
use crate::body::{Body, RequestBody};
use crate::exchange::{ConnInfo, Exchange};
use crate::files::FileBody;
use crate::msg::{Known, Method, ResponseHead, Status, Version};
use crate::net::Transport;
use crate::net::buf::{LARGE, SMALL};
use crate::pipeline;
use crate::pipeline::Response;
use crate::proto::h1::codec::{self, Framing, Limits, OutFraming, ParseError, Parsed};
use crate::proxy::relay::{self, RelayEnd, Rewrite, Tracker};
use crate::proxy::timer::Deadline;
use crate::runtime::{Core, CoreSnapshot};
use bytes::{Buf, Bytes, BytesMut};
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice};
use std::os::fd::AsFd;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::Duration;

/// An unread request body up to this size is read and dropped to keep the connection;
/// a longer one closes it.
const MAX_DRAIN: u64 = 64 * 1024;
/// How long a closing connection is read from, so the last response reaches a client that
/// is still sending.
const LINGER: Duration = Duration::from_secs(2);

/// Serves one connection until close, error, idle timeout or shutdown.
pub(crate) async fn serve(core: Rc<Core>, mut io: Transport, info: ConnInfo) {
    // Bytes of a pipelined next request that arrived with the previous one.
    let mut carry: Option<BytesMut> = None;
    let mut watch = Deadline::default();
    let drain = core.until_drain();
    tokio::pin!(drain);
    let mut drain_watched = false;
    let close = loop {
        if carry.is_none()
            && let Err(close) = idle(
                &core,
                &mut io,
                &mut watch,
                drain.as_mut(),
                &mut drain_watched,
            )
            .await
        {
            break close;
        }
        // Once per request: a reload takes effect on the next request of every connection.
        let snap = core.snapshot();
        let mut ex = core.exchanges.take(info, snap.plan.var_count);
        let mut buf = carry.take().unwrap_or_else(|| core.bufs.take());

        let head = match read_head(&snap, &mut io, &mut buf, &mut ex, &mut watch).await {
            Ok(head) => head,
            Err(close) => {
                answer_bad(&core, &mut io, &mut ex, &close).await;
                core.exchanges.put(ex);
                core.bufs.put(buf);
                break close;
            }
        };

        // The connection is lent to the pipeline as the request body; the borrow ends when
        // `handle` returns, before the response is written on the same connection.
        let mut state = BodyState::new(head.framing, head.expect_continue);
        let (resp, log) = pipeline::handle(
            &core,
            &snap,
            &mut ex,
            RequestBody::H1(H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            }),
        )
        .await;
        #[cfg(test)]
        crate::runtime::testing::observe(&core, &info);

        let status = resp.head.status;
        let mut sent = 0;
        let written = write_response(
            &core, &snap, &mut io, &mut buf, &mut state, &mut ex, resp, &head, &mut watch,
            &mut sent,
        )
        .await;
        if let Some(log) = log {
            access::record(&core, &snap, &ex, log, status, sent);
        }
        core.exchanges.put(ex);
        match written {
            Ok(()) if !buf.is_empty() => carry = Some(buf),
            Ok(()) => core.bufs.put(buf),
            Err(close) => {
                core.bufs.put(buf);
                break close;
            }
        }
    };
    match close {
        Close::Bad(_) | Close::SlowHead | Close::Unread => linger(&core, io).await,
        _ => io.close().await,
    }
}

/// Waits until the connection is readable without holding any buffer (idle keep-alive
/// connections cost only their socket and this task's state). Ends on keep-alive timeout or
/// shutdown.
async fn idle(
    core: &Core,
    io: &mut Transport,
    watch: &mut Deadline,
    mut drain: Pin<&mut impl Future<Output = ()>>,
    drain_watched: &mut bool,
) -> Result<(), Close> {
    watch.set(Some(core.snapshot().plan.server.keep_alive));
    let readable = io.readable();
    tokio::pin!(readable);
    poll_fn(|cx| {
        // A request that has arrived is answered even while draining, with `Connection:
        // close`: its client sent it before it could know, and it may be the first request of
        // a connection, which clients do not retry.
        if let Poll::Ready(ready) = readable.as_mut().poll(cx) {
            return Poll::Ready(ready.map_err(Close::Io));
        }
        if core.draining.get() {
            return Poll::Ready(Err(Close::Shutdown));
        }
        // Polled once per connection: the drain signal keeps this task's waker from then on,
        // and each later wait reads the flag above when it is woken. Polling it per wait
        // would take the signal's lock per request.
        if !*drain_watched {
            *drain_watched = true;
            if drain.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(Close::Shutdown));
            }
        }
        watch.poll_expired(cx).map(|()| Err(Close::Timeout))
    })
    .await
}

/// One read, bounded by the connection's deadline.
async fn read_some(
    io: &mut Transport,
    buf: &mut BytesMut,
    watch: &mut Deadline,
) -> Result<usize, Close> {
    let read = io.read(buf);
    tokio::pin!(read);
    poll_fn(|cx| match read.as_mut().poll(cx) {
        Poll::Ready(read) => Poll::Ready(read.map_err(Close::Io)),
        Poll::Pending => watch.poll_expired(cx).map(|()| Err(Close::Timeout)),
    })
    .await
}

/// Reads until the head is complete, parses it into `ex.req`, and leaves the body bytes that
/// arrived with it at the front of `buf`. The header timeout starts when a read leaves the
/// head incomplete; until then the keep-alive deadline of the idle wait still holds.
async fn read_head(
    snap: &CoreSnapshot,
    io: &mut Transport,
    buf: &mut BytesMut,
    ex: &mut Exchange,
    watch: &mut Deadline,
) -> Result<HeadInfo, Close> {
    let server = &snap.plan.server;
    let limits = Limits {
        max_head_bytes: server.max_head_bytes,
        max_header_fields: server.max_header_fields,
    };
    let mut started = false;
    loop {
        if !buf.is_empty() {
            match codec::parse_request(buf, &limits, &mut ex.req) {
                Ok(Parsed::Complete {
                    head_len,
                    framing,
                    extra,
                }) => {
                    buf.advance(head_len);
                    return Ok(HeadInfo {
                        framing,
                        keep_alive: extra.keep_alive,
                        expect_continue: extra.expect_continue,
                    });
                }
                Ok(Parsed::Partial) => {}
                Err(e) => return Err(Close::Bad(e)),
            }
            if !started {
                started = true;
                watch.set(Some(server.header_timeout));
            }
        }
        match read_some(io, buf, watch).await {
            Ok(0) => return Err(Close::Eof),
            Ok(_) => {}
            Err(Close::Timeout) if started => return Err(Close::SlowHead),
            Err(close) => return Err(close),
        }
    }
}

/// Answers a head that failed to parse (400, 431, 505) or took too long (408). No routing,
/// and site headers do not apply: there is no trustworthy host.
async fn answer_bad(core: &Core, io: &mut Transport, ex: &mut Exchange, close: &Close) {
    let status = match close {
        Close::Bad(e) => e.status(),
        Close::SlowHead => Status::new(408).expect("408 is a status code"),
        _ => return,
    };
    let head = ex.response_head(status);
    let date = *core.clock.http_date.borrow();
    ex.out.clear();
    codec::write_response_head(
        &head,
        Version::Http11,
        OutFraming::Length(0),
        false,
        Some(&date),
        &mut ex.out,
    );
    ex.recycle(head);
    let _ = io.write_all_vectored(&mut [IoSlice::new(&ex.out)]).await;
}

/// Writes the response and its body, choosing the cheapest path for the body kind (see
/// `body.rs`). `Ok` keeps the connection for the next request. It closes when either side
/// asked to, when the request matched no site, when the response is delimited by the close,
/// when the core is draining, and when the request body was neither read nor is short enough
/// to drain. `sent` counts the body bytes written after the head (for a tunnel, the bytes
/// relayed to the client), whether or not the response got out whole.
#[expect(
    clippy::too_many_arguments,
    reason = "the connection's pieces are borrowed separately"
)]
async fn write_response(
    core: &Core,
    snap: &CoreSnapshot,
    io: &mut Transport,
    buf: &mut BytesMut,
    state: &mut BodyState,
    ex: &mut Exchange,
    resp: Response,
    request: &HeadInfo,
    watch: &mut Deadline,
    sent: &mut u64,
) -> Result<(), Close> {
    let Response {
        head,
        body,
        upgrade,
        local,
    } = resp;
    if state.failed {
        ex.recycle(head);
        return Err(Close::Eof);
    }
    if let Some(mut upgrade) = upgrade {
        ex.out.clear();
        codec::write_response_head(
            &head,
            Version::Http11,
            OutFraming::None,
            true,
            None,
            &mut ex.out,
        );
        ex.recycle(head);
        if io
            .write_all_vectored(&mut [IoSlice::new(&ex.out)])
            .await
            .is_ok()
        {
            for buf in [&mut *buf, &mut upgrade.conn.buf] {
                if buf.is_empty() {
                    core.bufs
                        .put(std::mem::replace(buf, core.bufs.take_large()));
                }
            }
            let _ = relay::tunnel(io, buf, &mut upgrade.conn, upgrade.idle, sent).await;
        }
        core.bufs.put(std::mem::take(&mut upgrade.conn.buf));
        return Err(Close::Done);
    }

    let version = ex.req.version;
    let head_only = ex.req.method == Method::Head || !head.status.has_body();
    let body_left = state.discard(buf);
    let framing = if head_only {
        head_only_framing(local, &head, &body)
    } else {
        match &body {
            Body::Upstream(upstream) => match upstream.track.framing() {
                Framing::Chunked => OutFraming::ChunkedPassthrough,
                Framing::UntilClose => OutFraming::Chunked,
                Framing::None | Framing::Length(_) => {
                    OutFraming::Length(upstream.len().unwrap_or(0))
                }
            },
            Body::Encoded(_) => OutFraming::Chunked,
            known => OutFraming::Length(known.len().unwrap_or(0)),
        }
    };
    let chunked = matches!(
        framing,
        OutFraming::Chunked | OutFraming::ChunkedPassthrough
    );
    let keep = request.keep_alive
        && ex.site.is_some()
        && !core.draining.get()
        && !(chunked && version == Version::Http10)
        && matches!(body_left, Unread::None | Unread::Short);
    let date = local.then(|| *core.clock.http_date.borrow());
    ex.out.clear();
    codec::write_response_head(
        &head,
        version,
        framing,
        keep,
        date.as_ref().map(|d| &d[..]),
        &mut ex.out,
    );
    ex.recycle(head);

    let out = &ex.out[..];
    let sent = match body {
        body if head_only => {
            if let Body::Upstream(upstream) = body {
                upstream.finish(core);
            }
            io.write_all_vectored(&mut [IoSlice::new(out)]).await
        }
        Body::Empty => io.write_all_vectored(&mut [IoSlice::new(out)]).await,
        Body::Bytes(bytes) => {
            let written = io
                .write_all_vectored(&mut [IoSlice::new(out), IoSlice::new(&bytes)])
                .await;
            if written.is_ok() {
                *sent = bytes.len() as u64;
            }
            written
        }
        Body::File(file) => send_file(core, io, out, file, sent).await,
        Body::Upstream(mut upstream) => {
            let rewrite = match (upstream.track.framing(), version) {
                (Framing::Chunked, Version::Http10) => Rewrite::Unchunk,
                (Framing::UntilClose, Version::Http11) => Rewrite::Chunk,
                _ => Rewrite::Raw,
            };
            let end = relay::copy_response(core, out, &mut upstream, rewrite, io, buf, sent).await;
            upstream.finish(core);
            match end {
                RelayEnd::Complete => Ok(()),
                RelayEnd::Broken => Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
        mut stream @ Body::Encoded(_) => {
            send_stream(core, io, out, &mut stream, version != Version::Http10, sent).await
        }
    };
    sent.map_err(Close::Io)?;

    if !keep {
        // A client that may still be sending needs its bytes read, or the reset that
        // answers them can destroy the response on its way.
        let quiet = buf.is_empty() && body_left == Unread::None;
        return Err(if quiet { Close::Done } else { Close::Unread });
    }
    if body_left == Unread::Short {
        watch.set(Some(snap.plan.server.header_timeout));
        loop {
            match state.discard(buf) {
                Unread::None => break,
                Unread::Short if read_some(io, buf, watch).await? > 0 => {}
                Unread::Short => return Err(Close::Eof),
                Unread::Long => return Err(Close::Unread),
            }
        }
    }
    Ok(())
}

/// Framing fields of a response that carries no body (HEAD, 204, 304): the length the body
/// would have. A local body has it; a proxied response keeps what the origin declared.
fn head_only_framing(local: bool, head: &ResponseHead, body: &Body) -> OutFraming {
    if local {
        return body.len().map_or(OutFraming::Chunked, OutFraming::Length);
    }
    let fields = &head.fields;
    let declared = fields
        .get(Known::ContentLength)
        .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok());
    match declared {
        Some(n) => OutFraming::Length(n),
        None if fields.has_token(Known::TransferEncoding, b"chunked") => OutFraming::Chunked,
        None => OutFraming::None,
    }
}

/// A file body after `head`: sendfile on a kernel-plaintext socket, read and written
/// otherwise. `sent` counts the body bytes written.
async fn send_file(
    core: &Core,
    io: &mut Transport,
    head: &[u8],
    file: FileBody,
    sent: &mut u64,
) -> io::Result<()> {
    let sock = match io {
        Transport::Plain(sock) | Transport::Ktls(sock) => sock,
        Transport::Tls(_) => {
            return send_stream(core, io, head, &mut Body::File(file), false, sent).await;
        }
    };
    sock.write_all_vectored(&mut [IoSlice::new(head)]).await?;
    let len = file.range.end - file.range.start;
    let n = sock
        .sendfile(file.file.as_fd(), file.range.start, len)
        .await?;
    *sent = n;
    if n == len {
        Ok(())
    } else {
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

/// A body read chunk by chunk after `head`, each chunk written before the next is read.
/// `chunked` frames the chunks; without it the body's length or the close delimits it. `sent`
/// counts the bytes written after the head, chunk syntax included.
async fn send_stream(
    core: &Core,
    io: &mut Transport,
    mut head: &[u8],
    body: &mut Body,
    chunked: bool,
    sent: &mut u64,
) -> io::Result<()> {
    let mut size = [0u8; 18];
    loop {
        let chunk = body.next_chunk(core).await?;
        let data = chunk.as_deref().unwrap_or_default();
        let mut slices = relay::framed(head, data, chunked, chunk.is_none(), &mut size);
        let len: usize = slices.iter().map(|s| s.len()).sum();
        if len > 0 {
            io.write_all_vectored(&mut slices).await?;
            *sent += (len - head.len()) as u64;
        }
        head = &[];
        if chunk.is_none() {
            return Ok(());
        }
    }
}

/// Closes a connection whose client may still be sending: half-close, then read and drop
/// what arrives until the client closes or [`LINGER`] passes.
async fn linger(core: &Core, mut io: Transport) {
    use tokio::io::AsyncWriteExt;
    if io.shutdown().await.is_err() {
        return;
    }
    let mut buf = core.bufs.take();
    let _ = tokio::time::timeout(LINGER, async {
        while matches!(io.read(&mut buf).await, Ok(n) if n > 0) {
            buf.clear();
        }
    })
    .await;
    core.bufs.put(buf);
}

/// Why a connection ends; a client closing is not an error.
#[derive(Debug)]
pub(crate) enum Close {
    /// The client closed.
    Eof,
    /// Idle past the keep-alive timeout.
    Timeout,
    /// A request head started and did not finish within the header timeout; answered 408.
    SlowHead,
    Shutdown,
    Io(io::Error),
    /// The head did not parse; answered with its status.
    Bad(ParseError),
    /// The last response announced the close and the client has nothing more on the way.
    Done,
    /// The last response announced the close while request bytes were unread.
    Unread,
}

/// Facts the driver keeps from the parsed head.
pub(crate) struct HeadInfo {
    pub framing: Framing,
    pub keep_alive: bool,
    pub expect_continue: bool,
}

/// What is left of a request body after its request was answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unread {
    None,
    /// At most [`MAX_DRAIN`] bytes the client is already sending.
    Short,
    /// Too much, of unknown length, broken, or held back by the client until a
    /// `100 Continue` that was never sent.
    Long,
}

/// Progress through the request body. Owned by the driver (not by the body handed to the
/// pipeline), so after the handler returns the driver knows whether the body was fully read,
/// and drains or closes accordingly.
pub(crate) struct BodyState {
    pub track: Tracker,
    /// Bytes at the front of the connection's buffer that belong to the body and were not
    /// consumed yet. Everything behind them in the buffer has not been looked at.
    pending: usize,
    /// `100 Continue` still owed before the first read.
    pub expect_continue: bool,
    /// The body could not be read to its end: the client closed, failed, or sent broken
    /// chunk framing. The connection is closed without a response.
    pub failed: bool,
}

impl BodyState {
    pub fn new(framing: Framing, expect_continue: bool) -> Self {
        BodyState {
            track: Tracker::new(framing),
            pending: 0,
            expect_continue,
            failed: false,
        }
    }

    /// Whether the request has no body at all.
    pub fn is_empty(&self) -> bool {
        matches!(self.track.framing(), Framing::None | Framing::Length(0))
    }

    /// Whether every byte of the body was consumed.
    pub fn is_done(&self) -> bool {
        self.track.ended() && self.pending == 0
    }

    /// Looks at the bytes of `buf` not seen yet and counts those of the body as pending.
    fn absorb(&mut self, buf: &BytesMut) -> io::Result<()> {
        if self.track.ended() || buf.len() == self.pending {
            return Ok(());
        }
        match self.track.scan(&buf[self.pending..]) {
            Ok(n) => {
                self.pending += n;
                Ok(())
            }
            Err(_) => {
                self.failed = true;
                Err(io::ErrorKind::InvalidData.into())
            }
        }
    }

    /// Drops the body bytes `buf` holds and says what is still to come.
    fn discard(&mut self, buf: &mut BytesMut) -> Unread {
        if self.absorb(buf).is_err() {
            return Unread::Long;
        }
        buf.advance(self.pending);
        self.pending = 0;
        match self.track.remaining() {
            _ if self.track.ended() => Unread::None,
            Some(n) if n <= MAX_DRAIN && !self.expect_continue => Unread::Short,
            _ => Unread::Long,
        }
    }
}

/// The request body of an h1 request, read from the connection that the driver lends to the
/// pipeline. Bytes that arrived with the head are served first, from `buf`.
pub(crate) struct H1Body<'a> {
    pub io: &'a mut Transport,
    pub buf: &'a mut BytesMut,
    pub state: &'a mut BodyState,
}

impl H1Body<'_> {
    /// The raw body bytes that are already here, possibly none. Never reads.
    pub fn buffered(&mut self) -> io::Result<&[u8]> {
        self.state.absorb(self.buf)?;
        Ok(&self.buf[..self.state.pending])
    }

    /// Relay fast path for the proxy: raw framed bytes (a chunked body with its chunk
    /// syntax) straight from `buf`, refilled from `io` when it holds none. `None` at the end
    /// of the body. The same bytes come back until they are consumed.
    pub async fn raw(&mut self) -> io::Result<Option<&[u8]>> {
        loop {
            self.state.absorb(self.buf)?;
            if self.state.pending > 0 {
                return Ok(Some(&self.buf[..self.state.pending]));
            }
            if self.state.track.ended() {
                return Ok(None);
            }
            self.fill().await?;
        }
    }

    /// Marks `n` raw bytes as forwarded.
    pub fn consume(&mut self, n: usize) {
        self.buf.advance(n);
        self.state.pending -= n;
    }

    /// Generic path: the next piece of body data, without chunk syntax. Not to be mixed
    /// with [`H1Body::raw`] on one body.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        loop {
            let data = relay::take_data(&mut self.state.track, self.buf);
            let Ok(data) = data else {
                self.state.failed = true;
                return Err(io::ErrorKind::InvalidData.into());
            };
            if data.is_some() || self.state.track.ended() {
                return Ok(data);
            }
            self.fill().await?;
        }
    }

    /// Moves a body that has much left to a 64 KiB buffer, once the small one is empty.
    pub fn prefer_large(&mut self, core: &Core) {
        let long = self
            .state
            .track
            .remaining()
            .is_none_or(|n| n > SMALL as u64);
        if long && !self.state.track.ended() && self.buf.is_empty() && self.buf.capacity() < LARGE {
            core.bufs
                .put(std::mem::replace(self.buf, core.bufs.take_large()));
        }
    }

    /// Reads more of the body, after telling a client that waits for it to go ahead.
    async fn fill(&mut self) -> io::Result<()> {
        let read = async {
            if self.state.expect_continue {
                self.state.expect_continue = false;
                self.io
                    .write_all_vectored(&mut [IoSlice::new(codec::CONTINUE)])
                    .await?;
            }
            match self.io.read(self.buf).await? {
                0 => Err(io::ErrorKind::UnexpectedEof.into()),
                _ => Ok(()),
            }
        }
        .await;
        self.state.failed |= read.is_err();
        read
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Socket;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    /// A transport on one end of a socket pair, and the blocking other end as the client.
    fn pair() -> (Transport, UnixStream) {
        let (ours, theirs) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let io = Transport::Plain(Socket::from_fd(ours.into()).unwrap());
        (io, theirs)
    }

    fn block_on<T>(test: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test)
    }

    /// Everything `raw` hands out until the body ends, each piece consumed whole.
    async fn drain_raw(body: &mut H1Body<'_>) -> Vec<Vec<u8>> {
        let mut pieces = Vec::new();
        while let Some(piece) = body.raw().await.unwrap() {
            let piece = piece.to_vec();
            body.consume(piece.len());
            pieces.push(piece);
        }
        pieces
    }

    #[test]
    fn a_body_with_a_length_stops_at_its_last_byte() {
        block_on(async {
            let (mut io, mut client) = pair();
            let mut buf = BytesMut::from(&b"hel"[..]);
            let mut state = BodyState::new(Framing::Length("hello world".len() as u64), false);
            assert!(!state.is_empty() && !state.is_done());
            let mut body = H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            };
            assert_eq!(body.buffered().unwrap(), b"hel", "what came with the head");
            assert_eq!(body.raw().await.unwrap(), Some(&b"hel"[..]));
            assert_eq!(
                body.raw().await.unwrap(),
                Some(&b"hel"[..]),
                "unconsumed bytes are handed out again"
            );
            body.consume(3);
            client.write_all(b"lo worldGET /next HTTP/1.1\r\n").unwrap();
            assert_eq!(body.raw().await.unwrap(), Some(&b"lo world"[..]));
            body.consume(7);
            assert_eq!(body.raw().await.unwrap(), Some(&b"d"[..]));
            body.consume(1);
            assert_eq!(body.raw().await.unwrap(), None);
            assert!(state.is_done());
            assert_eq!(
                &buf[..],
                b"GET /next HTTP/1.1\r\n",
                "the next request stays in the buffer"
            );
        });
    }

    #[test]
    fn a_chunked_body_is_followed_across_reads_to_its_last_chunk() {
        block_on(async {
            let (mut io, mut client) = pair();
            let mut buf = BytesMut::from(&b"4\r\nwi"[..]);
            let mut state = BodyState::new(Framing::Chunked, false);
            let mut body = H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            };
            let writer = std::thread::spawn(move || {
                for part in [&b"ki\r\n5\r\npedia"[..], b"\r\n0\r\n\r\nGET /next"] {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    client.write_all(part).unwrap();
                }
                client
            });
            let raw = drain_raw(&mut body).await.concat();
            assert_eq!(
                raw, b"4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n",
                "the chunk syntax is handed out as it was sent"
            );
            assert!(state.is_done());
            assert_eq!(&buf[..], b"GET /next");
            writer.join().unwrap();
        });
    }

    #[test]
    fn next_chunk_yields_the_data_of_a_chunked_body() {
        block_on(async {
            let (mut io, mut client) = pair();
            let mut buf = BytesMut::from(&b"4\r\nwiki\r\n5;x=y\r\npe"[..]);
            let mut state = BodyState::new(Framing::Chunked, false);
            let mut body = H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            };
            client.write_all(b"dia\r\n0\r\n\r\n").unwrap();
            let mut data = Vec::new();
            while let Some(chunk) = body.next_chunk().await.unwrap() {
                data.extend_from_slice(&chunk);
            }
            assert_eq!(data, b"wikipedia");
            assert!(state.is_done());
        });
    }

    #[test]
    fn continue_is_sent_once_when_the_body_is_first_read_for() {
        block_on(async {
            let (mut io, mut client) = pair();
            let mut buf = BytesMut::new();
            let mut state = BodyState::new(Framing::Length(4), true);
            let mut body = H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            };
            assert_eq!(body.buffered().unwrap(), b"", "looking sends nothing");
            let writer = std::thread::spawn(move || {
                let mut interim = [0u8; 25];
                client.read_exact(&mut interim).unwrap();
                assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
                client.write_all(b"da").unwrap();
                std::thread::sleep(std::time::Duration::from_millis(20));
                client.write_all(b"ta").unwrap();
                client.shutdown(std::net::Shutdown::Write).unwrap();
                let mut rest = Vec::new();
                client.read_to_end(&mut rest).unwrap();
                rest
            });
            assert_eq!(drain_raw(&mut body).await.concat(), b"data");
            drop(io);
            assert_eq!(writer.join().unwrap(), b"", "one interim response, not two");
        });
    }

    #[test]
    fn a_client_that_closes_mid_body_fails_the_body() {
        block_on(async {
            let (mut io, mut client) = pair();
            let mut buf = BytesMut::new();
            let mut state = BodyState::new(Framing::Length(10), false);
            client.write_all(b"half").unwrap();
            drop(client);
            let mut body = H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            };
            assert_eq!(body.raw().await.unwrap(), Some(&b"half"[..]));
            body.consume(4);
            let end = body.raw().await.unwrap_err();
            assert_eq!(end.kind(), io::ErrorKind::UnexpectedEof);
            assert!(state.failed && !state.is_done());
        });
    }

    #[test]
    fn broken_chunk_framing_fails_the_body() {
        block_on(async {
            let (mut io, _client) = pair();
            let mut buf = BytesMut::from(&b"zz\r\nnot hex"[..]);
            let mut state = BodyState::new(Framing::Chunked, false);
            let mut body = H1Body {
                io: &mut io,
                buf: &mut buf,
                state: &mut state,
            };
            assert_eq!(
                body.raw().await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert!(state.failed);
        });
    }

    #[test]
    fn an_unread_body_is_classified_by_what_is_still_to_come() {
        let unread = |framing, expect, buffered: &[u8]| {
            let mut state = BodyState::new(framing, expect);
            let mut buf = BytesMut::from(buffered);
            (state.discard(&mut buf), buf)
        };
        let (left, buf) = unread(Framing::None, false, b"GET /next");
        assert_eq!((left, &buf[..]), (Unread::None, &b"GET /next"[..]));
        let (left, buf) = unread(Framing::Length(4), false, b"bodyGET /next");
        assert_eq!(
            (left, &buf[..]),
            (Unread::None, &b"GET /next"[..]),
            "a body that arrived with its head is dropped from the buffer"
        );
        assert_eq!(unread(Framing::Length(4), false, b"bo").0, Unread::Short);
        assert_eq!(
            unread(Framing::Length(MAX_DRAIN), false, b"").0,
            Unread::Short
        );
        assert_eq!(
            unread(Framing::Length(MAX_DRAIN + 1), false, b"").0,
            Unread::Long
        );
        assert_eq!(
            unread(Framing::Length(4), true, b"").0,
            Unread::Long,
            "a client waiting for 100 Continue may never send the body"
        );
        assert_eq!(unread(Framing::Chunked, false, b"4\r\nwi").0, Unread::Long);
        assert_eq!(
            unread(Framing::Chunked, false, b"0\r\n\r\n").0,
            Unread::None
        );
        assert_eq!(unread(Framing::Chunked, false, b"zz\r\n").0, Unread::Long);
    }
}
