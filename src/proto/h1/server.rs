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
//! Four socket syscalls per request, zero heap allocations, zero atomics. The io_uring
//! backend keeps the same driver and removes the per-request syscalls into one
//! batched `io_uring_enter` per loop turn.
//!
//! # Where buffers live
//!
//! - Downstream read buffer: core `BufPool` (16 KiB), lent while a request is in progress;
//!   kept across requests only when it holds pipelined bytes.
//! - Request/response heads, arena, `out`: the `Exchange` (core `ExchangePool`).
//! - Upstream read buffer: lent from the core `BufPool` while the upstream connection is
//!   checked out; a connection is pooled only with an empty buffer.
//! - Body relays: in place in whichever read buffer the bytes arrived in; large transfers
//!   switch to a 64 KiB pool buffer (or splice/sendfile when both ends are kernel plaintext).

use crate::body::RequestBody;
use crate::exchange::{ConnInfo, Exchange};
use crate::net::Transport;
use crate::pipeline;
use crate::pipeline::Response;
use crate::proto::h1::codec::{Chunked, Framing, ParseError};
use crate::runtime::{Core, CoreSnapshot};
use bytes::{Bytes, BytesMut};
use std::io;
use std::rc::Rc;

/// Serves one connection until close, error, idle timeout or shutdown.
pub(crate) async fn serve(core: Rc<Core>, mut io: Transport, info: ConnInfo) {
    // Bytes of a pipelined next request that arrived with the previous one.
    let mut carry: Option<BytesMut> = None;
    loop {
        if carry.is_none() && idle(&core, &mut io).await.is_err() {
            break;
        }
        // Once per request: a reload takes effect on the next request of every connection.
        let snap = core.snapshot();
        let mut ex = core.exchanges.take(info, snap.plan.var_count);
        let mut buf = carry.take().unwrap_or_else(|| core.bufs.take());

        let extra = match read_head(&core, &snap, &mut io, &mut buf, &mut ex).await {
            Ok(extra) => extra,
            Err(close) => {
                answer_bad(&core, &mut io, &mut ex, &close).await;
                core.exchanges.put(ex);
                core.bufs.put(buf);
                break;
            }
        };

        // The connection is lent to the pipeline as the request body; the borrow ends when
        // `handle` returns, before the response is written on the same connection.
        let mut state = BodyState::new(extra.framing, extra.expect_continue);
        let resp = pipeline::handle(
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

        let keep = write_response(
            &core, &snap, &mut io, &mut buf, &mut state, &mut ex, resp, &extra,
        )
        .await;
        core.exchanges.put(ex);
        match keep {
            Ok(true) if !buf.is_empty() => carry = Some(buf),
            Ok(true) => core.bufs.put(buf),
            _ => {
                core.bufs.put(buf);
                break;
            }
        }
    }
    io.close().await;
}

/// Writes a 400/431/505 for a head that failed to parse (no routing, site headers do not
/// apply: there is no trustworthy host).
async fn answer_bad(core: &Core, io: &mut Transport, ex: &mut Exchange, close: &Close) {
    todo!()
}

/// Waits until the connection is readable without holding any buffer (idle keep-alive
/// connections cost only their socket and this task's state). Ends on keep-alive timeout or
/// shutdown.
async fn idle(core: &Core, io: &mut Transport) -> Result<(), Close> {
    todo!()
}

/// Reads until the head is complete (header timeout), parses it into `ex.req`, and leaves the
/// body bytes that arrived with it at the front of `buf`.
async fn read_head(
    core: &Core,
    snap: &CoreSnapshot,
    io: &mut Transport,
    buf: &mut BytesMut,
    ex: &mut Exchange,
) -> Result<HeadInfo, Close> {
    todo!()
}

/// Writes the response and its body, choosing the cheapest path for the body kind (see
/// `body.rs`). Returns whether the connection stays open: not if either side asked to close,
/// if the request body was not fully consumed (and draining it would exceed 64 KiB), or if the
/// response was EOF-delimited.
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
    extra: &HeadInfo,
) -> Result<bool, Close> {
    // 1. If resp.upgrade: write 101 head, then proxy::relay::tunnel(io, buf, upgrade) to the end.
    // 2. codec::write_response_head(&resp.head, .., ex.out); date from core.clock when resp.local.
    // 3. match resp.body { Bytes -> writev [out, bytes]; File -> write head, sendfile or
    //    pread loop; Upstream -> relay::copy_response(io, ex.out, upstream) ; Encoded -> chunks }
    todo!()
}

/// Why a connection ends; logged at debug only (a client closing is not an error).
#[derive(Debug)]
pub(crate) enum Close {
    Eof,
    Timeout,
    Shutdown,
    Io(io::Error),
    /// Answered with this status, then closed.
    Bad(ParseError),
}

/// Facts the driver keeps from the parsed head.
pub(crate) struct HeadInfo {
    pub framing: Framing,
    pub keep_alive: bool,
    pub expect_continue: bool,
    pub upgrade: bool,
}

/// Progress through the request body. Owned by the driver (not by the body handed to the
/// pipeline), so after the handler returns the driver knows whether the body was fully read,
/// and drains or closes accordingly.
pub(crate) struct BodyState {
    pub framing: Framing,
    pub chunked: Chunked,
    pub remaining: u64,
    /// `100 Continue` still owed before the first read.
    pub expect_continue: bool,
}

impl BodyState {
    pub fn new(framing: Framing, expect_continue: bool) -> Self {
        todo!()
    }
    pub fn is_done(&self) -> bool {
        todo!()
    }
}

/// The request body of an h1 request, read from the connection that the driver lends to the
/// pipeline. Bytes that arrived with the head are served first, from `buf`.
pub(crate) struct H1Body<'a> {
    pub io: &'a mut Transport,
    pub buf: &'a mut BytesMut,
    pub state: &'a mut BodyState,
}

impl<'a> H1Body<'a> {
    /// Relay fast path for the proxy: hands out raw framed bytes (chunked passthrough when the
    /// upstream request is also chunked) straight from `buf`, refilling it from `io`.
    pub async fn raw(&mut self) -> io::Result<Option<&[u8]>> {
        todo!()
    }
    /// Marks `n` raw bytes as forwarded.
    pub fn consume(&mut self, n: usize) {
        todo!()
    }
    /// Generic path: decoded data chunks.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        todo!()
    }
}
