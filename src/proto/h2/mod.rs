//! HTTP/2 downstream (TLS with ALPN h2 only; no h2c), built for this proxy: one task per
//! connection does everything for its streams.
//!
//! - [`frame`], [`hpack`], [`huffman`]: the wire formats.
//! - [`engine`]: the protocol's state and limits, without IO.
//! - This module: the driver that moves bytes between the transport and the engine, and the
//!   work of each stream (`pipeline::handle`, then the response).
//!
//! # One wake of a connection
//!
//! 1. Read what the transport has. Frames are parsed where they were read; a request's
//!    field block is decoded straight into an exchange's head.
//! 2. Once the transport has no more, each request that arrived starts, on the connection
//!    task. Work that never waits (files, respond, redirect, errors) is finished there and
//!    then, its HEADERS and DATA in the outbox. Work that waits (an upstream) is kept and
//!    polled again when something wakes it ([`wake`]).
//! 3. Everything queued during the wake leaves in one vectored write, which over TLS is as
//!    few records as hold it.
//!
//! Requests start after the frames that came with them, so those frames meet a stream that
//! is still open: a body's first DATA is there when the work first asks, an invalid frame is
//! answered as the stream error it is, and a request reset in the same breath never starts.
//! A RST_STREAM that arrives later drops the stream's work before the next frame is read: an
//! upstream exchange in progress is closed, never pooled. Draining and the keep-alive
//! timeout (a connection without streams) shut down gracefully: the streams in progress
//! finish, and a GOAWAY that names the last stream served ends the connection
//! (`Engine::start_shutdown`).
//!
//! Extended CONNECT is not advertised, so browsers open WebSockets over HTTP/1.1, the only
//! upgrade path.
//!
//! # Allocations
//!
//! None per stream once a connection and its core are warm: the exchange, the block the
//! work runs in and the read buffer come from per-core pools; stream slots, their wakers,
//! the outbox and both compression tables belong to the connection and are reused. The lib
//! test `allocations_per_stream` measures it.

mod engine;
mod frame;
mod hpack;
mod huffman;
mod task;
mod wake;

#[cfg(test)]
mod tests;

use crate::body::{Body, RequestBody};
use crate::exchange::{ConnInfo, Exchange};
use crate::log::debug;
use crate::msg::{Known, Method, ResponseHead, Status};
use crate::net::Transport;
use crate::net::buf::SMALL;
use crate::observe::{self, Started};
use crate::pipeline::{self, Response};
use crate::proxy::timer::Deadline;
use crate::runtime::{Core, CoreSnapshot};
use bytes::{Buf, Bytes, BytesMut};
use engine::{Begin, Engine, Event, Opened, SHARE_MIN, Step};
use frame::Reason;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};
use std::time::Duration;
use task::Task;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use wake::Ready;

/// Spare room a read asks for.
const MIN_READ: usize = 4096;
/// Reads and turns one wake of a connection takes before it lets other connections run.
const READS: usize = 16;
const TURNS: usize = 16;
/// How long each step of a shutdown waits: the streams in progress to finish before the
/// GOAWAY, then the client to acknowledge the GOAWAY that announces it.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(1);
/// How long a closing connection waits for the client to close its side, and how much it
/// reads meanwhile. Closing with input unread resets the connection, which can discard the
/// last frames on their way to the client.
const LINGER: Duration = Duration::from_secs(1);
const LINGER_BYTES: usize = 64 * 1024;

/// What a connection's driver and the work of its streams share. The engine is borrowed
/// for single calls, never across a wait.
pub(crate) struct Conn {
    engine: RefCell<Engine>,
    ready: Arc<Ready>,
}

/// Serves one connection until the client closes it, a connection error, the idle timeout
/// or the end of a drain.
pub(crate) async fn serve(core: Rc<Core>, io: Transport, info: ConnInfo) {
    let server = core.snapshot().plan.server.clone();
    let ready = Ready::new(Engine::slots(server.max_streams));
    let conn = Conn {
        engine: RefCell::new(Engine::new(
            ready.clone(),
            server.max_streams,
            server.max_header_fields,
            core.clock.unix.get(),
        )),
        ready,
    };
    let mut driver = Driver {
        core: &core,
        conn: &conn,
        info,
        io,
        rx: None,
        arrived: Vec::new(),
        tasks: Vec::new(),
        wakers: Vec::new(),
        cancelled: Vec::new(),
        watch: Deadline::default(),
        header_timeout: server.header_timeout,
        keep_alive: server.keep_alive,
        started: Instant::now(),
        block_since: None,
        idle_since: None,
        unwritten_since: None,
        shutdown_at: None,
        shutting_down: false,
        served: false,
        wrote: false,
    };
    let mut drain = pin!(core.until_drain());
    let end = poll_fn(|cx| driver.poll(cx, drain.as_mut())).await;
    driver.close(end).await;
}

/// How a connection ends.
enum End {
    /// Nothing left to do after a shutdown.
    Done,
    /// A connection error: GOAWAY with the reason.
    Failed(Reason),
    /// The client is gone or never spoke.
    Gone,
}

struct Driver<'a> {
    core: &'a Core,
    conn: &'a Conn,
    info: ConnInfo,
    io: Transport,
    /// Received bytes not yet handled; from the core's pool while there are any.
    rx: Option<BytesMut>,
    /// Requests whose work has not started.
    arrived: Vec<Arrived>,
    /// The work of each stream that is waiting, by slot.
    tasks: Vec<Option<Task<'a>>>,
    wakers: Vec<Waker>,
    cancelled: Vec<u32>,
    watch: Deadline,
    header_timeout: Duration,
    keep_alive: Duration,
    started: Instant,
    /// Since when a field block has been waiting for CONTINUATION.
    block_since: Option<Instant>,
    /// Since when the connection has had no stream.
    idle_since: Option<Instant>,
    /// Since when output has been waiting for the client to read.
    unwritten_since: Option<Instant>,
    /// When the current step of a shutdown stops waiting.
    shutdown_at: Option<Instant>,
    shutting_down: bool,
    /// A stream started since the idle clock was last set.
    served: bool,
    /// Output was written since the engine was last told.
    wrote: bool,
}

/// A request between its HEADERS and the start of its work.
struct Arrived {
    slot: u32,
    begin: Begin,
    snap: Rc<CoreSnapshot>,
    ex: Box<Exchange>,
}

impl<'a> Driver<'a> {
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        mut drain: Pin<&mut impl Future<Output = ()>>,
    ) -> Poll<End> {
        let conn = self.conn;
        conn.ready.listen(cx.waker());
        conn.engine.borrow_mut().set_now(self.core.clock.unix.get());
        for _ in 0..TURNS {
            let mut reads = 0;
            // Frames first: a turn that ended with the outbox full left some unhandled.
            let congested = loop {
                if let Err(reason) = self.frames() {
                    return Poll::Ready(End::Failed(reason));
                }
                if conn.engine.borrow().congested() {
                    break true;
                }
                if reads == READS {
                    break false;
                }
                match self.read(cx) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Poll::Ready(End::Gone),
                    Poll::Ready(Ok(_)) => reads += 1,
                    Poll::Pending => break false,
                }
            };
            self.start_arrived();
            conn.ready.take(|slot| self.resume(slot));
            match self.flush(cx) {
                Poll::Ready(Ok(())) => self.unwritten_since = None,
                Poll::Ready(Err(_)) => return Poll::Ready(End::Gone),
                // The wait for the client starts over with every byte it takes.
                Poll::Pending if self.wrote || self.unwritten_since.is_none() => {
                    self.unwritten_since = Some(Instant::now());
                }
                Poll::Pending => {}
            }
            if std::mem::take(&mut self.wrote) {
                conn.engine.borrow_mut().written();
            }
            // Another turn when there may be more to do right away: input beyond this
            // turn's reads, frames or reads held back by a full outbox that has room again,
            // work marked ready while other work ran or by the room the write made.
            let room = congested && !conn.engine.borrow().congested();
            if reads == READS || room || conn.ready.any() {
                continue;
            }
            // Nothing more to do now. Every source of more has this task's waker: the
            // transport (the read, or the flush of a full outbox, was pending) and the
            // streams' work.
            self.settle();
            if conn.engine.borrow().finished() && self.unwritten_since.is_none() {
                return Poll::Ready(End::Done);
            }
            if !self.shutting_down && drain.as_mut().poll(cx).is_ready() {
                self.shut_down(Instant::now());
                continue;
            }
            self.watch.set_at(self.deadline());
            if self.watch.poll_expired(cx).is_pending() {
                return Poll::Pending;
            }
            if let Some(end) = self.expired() {
                return Poll::Ready(end);
            }
        }
        // A connection this busy lets the others run.
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    /// One read into the receive buffer. An idle connection holds no buffer.
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let rx = self.rx.get_or_insert_with(|| self.core.bufs.take());
        if rx.capacity() - rx.len() < MIN_READ {
            rx.reserve(SMALL);
        }
        let mut spare = ReadBuf::uninit(rx.spare_capacity_mut());
        let polled = Pin::new(&mut self.io).poll_read(cx, &mut spare);
        let n = spare.filled().len();
        // SAFETY: the transport initialised the `n` bytes it filled of the spare capacity.
        unsafe { rx.set_len(rx.len() + n) };
        if rx.is_empty()
            && let Some(rx) = self.rx.take()
        {
            self.core.bufs.put(rx);
        }
        ready!(polled)?;
        Poll::Ready(Ok(n))
    }

    /// Handles the whole frames in the receive buffer, until the outbox is full.
    fn frames(&mut self) -> Result<(), Reason> {
        let conn = self.conn;
        loop {
            let Some(rx) = self.rx.as_mut() else {
                return Ok(());
            };
            let mut engine = conn.engine.borrow_mut();
            if engine.congested() {
                return Ok(());
            }
            match engine.step(rx)? {
                Step::More => break,
                Step::Done { len, event } => {
                    rx.advance(len);
                    drop(engine);
                    self.follow(event);
                }
                Step::Data {
                    len,
                    slot,
                    start,
                    end,
                } if end - start >= SHARE_MIN.max(rx.capacity() / 2) => {
                    rx.advance(start);
                    let data = rx.split_to(end - start).freeze();
                    rx.advance(len - end);
                    engine.deliver(slot, data);
                }
                Step::Data {
                    len,
                    slot,
                    start,
                    end,
                } => {
                    engine.deliver_copy(slot, &rx[start..end]);
                    rx.advance(len);
                }
                Step::Block {
                    len,
                    block,
                    fragment,
                } => {
                    // Once per request, as on h1: a reload applies to the next stream.
                    let snap = self.core.snapshot();
                    let mut ex = self.core.exchanges.take(self.info, snap.plan.var_count);
                    let fragment = fragment.map(|(start, end)| &rx[start..end]);
                    let opened = engine.open(block, fragment, &mut ex.req);
                    rx.advance(len);
                    drop(engine);
                    match opened? {
                        Opened::Request { slot, begin } => self.arrived.push(Arrived {
                            slot,
                            begin,
                            snap,
                            ex,
                        }),
                        Opened::Not(event) => {
                            self.core.exchanges.put(ex);
                            self.follow(event);
                        }
                    }
                }
            }
        }
        if conn.engine.borrow().in_block() {
            self.block_since.get_or_insert_with(Instant::now);
        } else {
            self.block_since = None;
        }
        Ok(())
    }

    fn follow(&mut self, event: Event) {
        match event {
            Event::None => {}
            Event::Cancel { slot } => self.cancel(slot),
        }
    }

    /// Drops the work of a stream that is over, which closes what it held (an upstream
    /// exchange in progress, a file). A request that has not started never does.
    fn cancel(&mut self, slot: u32) {
        if let Some(at) = self.arrived.iter().position(|a| a.slot == slot) {
            self.core.exchanges.put(self.arrived.remove(at).ex);
        } else if let Some(task) = self.tasks.get_mut(slot as usize) {
            *task = None;
        }
        self.conn.engine.borrow_mut().release(slot);
    }

    /// Starts the work of the requests that arrived, in order.
    fn start_arrived(&mut self) {
        if self.arrived.is_empty() {
            return;
        }
        self.served = true;
        let mut arrived = std::mem::take(&mut self.arrived);
        for Arrived {
            slot,
            begin,
            snap,
            ex,
        } in arrived.drain(..)
        {
            self.start(slot, begin, snap, ex);
        }
        // Nothing arrives while work runs: frames are read between, not during.
        self.arrived = arrived;
    }

    /// Starts a stream's work and runs it as far as it gets without waiting.
    fn start(&mut self, slot: u32, begin: Begin, snap: Rc<CoreSnapshot>, ex: Box<Exchange>) {
        let index = slot as usize;
        while self.wakers.len() <= index {
            let next = self.wakers.len() as u32;
            self.wakers.push(self.conn.ready.waker(next));
            self.tasks.push(None);
        }
        let mut task = Task::new(stream(self.conn, self.core, snap, ex, slot, begin));
        match task.poll(&mut Context::from_waker(&self.wakers[index])) {
            Poll::Ready(()) => {
                drop(task);
                self.conn.engine.borrow_mut().finish(slot);
            }
            Poll::Pending => self.tasks[index] = Some(task),
        }
    }

    /// Polls the work of a slot that was marked ready.
    fn resume(&mut self, slot: u32) {
        let index = slot as usize;
        let Some(task) = self.tasks.get_mut(index).and_then(Option::as_mut) else {
            return;
        };
        if task
            .poll(&mut Context::from_waker(&self.wakers[index]))
            .is_ready()
        {
            self.tasks[index] = None;
            self.conn.engine.borrow_mut().finish(slot);
        }
    }

    /// Writes the outbox: everything queued since the last write in one vectored write
    /// (more when the transport takes less), then the transport's own flush.
    fn flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut engine = self.conn.engine.borrow_mut();
            if engine.out.is_empty() {
                break;
            }
            let mut slices = SmallVec::new();
            engine.out.slices(&mut slices);
            let n = ready!(Pin::new(&mut self.io).poll_write_vectored(cx, &slices))?;
            drop(slices);
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            engine.out.advance(n);
            self.wrote = true;
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// Updates the idle clock at the end of a wake.
    fn settle(&mut self) {
        if self.conn.engine.borrow().streams() > 0 {
            self.idle_since = None;
            self.served = false;
        } else if self.idle_since.is_none() || std::mem::take(&mut self.served) {
            self.idle_since = Some(Instant::now());
        }
    }

    fn shut_down(&mut self, now: Instant) {
        self.shutting_down = true;
        self.shutdown_at = Some(now + SHUTDOWN_WAIT);
        self.conn.engine.borrow_mut().start_shutdown();
    }

    /// When the connection next has to act if nothing arrives: the client's preface or the
    /// rest of a field block within the header timeout, a stream within the keep-alive
    /// timeout, room to send within the same, the next step of a shutdown.
    fn deadline(&self) -> Option<Instant> {
        let engine = self.conn.engine.borrow();
        // The core's clock counts whole seconds, so a stalled stream is due a second past
        // the keep-alive timeout. Once that has passed the deadline is now: the poll that
        // computes it also finds it expired and resets the stream.
        let stalled = engine.stalled_since().map(|since| {
            let waited = (self.core.clock.unix.get() - since).max(0) as u64;
            let due = self.keep_alive + Duration::from_secs(1);
            Instant::now() + due.saturating_sub(Duration::from_secs(waited))
        });
        [
            engine
                .starting()
                .then_some(self.started + self.header_timeout),
            self.block_since.map(|since| since + self.header_timeout),
            self.idle_since
                .filter(|_| !self.shutting_down)
                .map(|since| since + self.keep_alive),
            self.unwritten_since.map(|since| since + self.keep_alive),
            stalled,
            self.shutdown_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Acts on the deadlines that have passed. `Some` ends the connection.
    fn expired(&mut self) -> Option<End> {
        let now = Instant::now();
        let past = |at: Instant| at <= now;
        let conn = self.conn;
        if conn.engine.borrow().starting() && past(self.started + self.header_timeout) {
            return Some(End::Gone);
        }
        if self
            .block_since
            .is_some_and(|since| past(since + self.header_timeout))
        {
            return Some(End::Failed(Reason::EnhanceYourCalm));
        }
        if self
            .unwritten_since
            .is_some_and(|since| past(since + self.keep_alive))
        {
            return Some(End::Gone);
        }
        if self.shutdown_at.is_some_and(past) {
            let more = conn.engine.borrow_mut().shutdown_waited();
            self.shutdown_at = more.then_some(now + SHUTDOWN_WAIT);
        }
        if !self.shutting_down
            && self
                .idle_since
                .is_some_and(|since| past(since + self.keep_alive))
        {
            self.shut_down(now);
        }
        let before = self.core.clock.unix.get() - self.keep_alive.as_secs() as i64;
        conn.engine
            .borrow_mut()
            .reset_stalled(before, &mut self.cancelled);
        while let Some(slot) = self.cancelled.pop() {
            self.cancel(slot);
        }
        None
    }

    /// Ends the connection: the streams' work is dropped, a connection error is told to the
    /// client, and the transport is closed once the client has closed its side or [`LINGER`]
    /// has passed.
    async fn close(mut self, end: End) {
        self.arrived.clear();
        self.tasks.clear();
        if let Some(rx) = self.rx.take() {
            self.core.bufs.put(rx);
        }
        match end {
            End::Gone => return,
            End::Done => {}
            End::Failed(reason) => {
                debug!(
                    "core {}: h2 from {}: {reason:?}",
                    self.core.index, self.info.remote
                );
                self.conn.engine.borrow_mut().fail(reason);
            }
        }
        let core = self.core;
        let _ = tokio::time::timeout(LINGER, async {
            poll_fn(|cx| self.flush(cx)).await?;
            poll_fn(|cx| Pin::new(&mut self.io).poll_shutdown(cx)).await?;
            let mut unread = core.bufs.take();
            let mut left = LINGER_BYTES;
            while left > 0 {
                unread.clear();
                match self.io.read(&mut unread).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => left = left.saturating_sub(n),
                }
            }
            core.bufs.put(unread);
            io::Result::Ok(())
        })
        .await;
    }
}

/// The work of one stream: the pipeline, then the response head and its body as DATA
/// frames from `Body::next_chunk`. Dropped where it stands when the stream is reset.
async fn stream<'a>(
    conn: &'a Conn,
    core: &'a Core,
    snap: Rc<CoreSnapshot>,
    ex: Box<Exchange>,
    slot: u32,
    begin: Begin,
) {
    let mut request = Request {
        core,
        snap: &snap,
        ex: Some(ex),
        answered: None,
        sent: 0,
    };
    let Some(ex) = request.ex.as_deref_mut() else {
        return;
    };
    let (resp, log) = match begin.preset {
        Some(status) => (pipeline::bare(ex, status), None),
        None => {
            let body = match begin.end_stream {
                true => RequestBody::Empty,
                false => RequestBody::H2(H2Body {
                    conn,
                    slot,
                    len: begin.length,
                }),
            };
            pipeline::handle(core, &snap, ex, body).await
        }
    };
    #[cfg(test)]
    crate::runtime::testing::observe(core, &ex.conn);

    let Response {
        head, body, local, ..
    } = resp;
    let status = head.status;
    let head_only = ex.req.method == Method::Head || !status.has_body();
    let length = if head_only {
        head_only_length(local, &head, &body)
    } else {
        body.len()
    };
    let empty = head_only || length == Some(0);
    {
        let date = local.then(|| *core.clock.http_date.borrow());
        let mut engine = conn.engine.borrow_mut();
        engine.send_head(slot, status, &head.fields, length, date.as_ref(), empty);
    }
    ex.recycle(head);
    request.answered = Some((log, status));

    if empty {
        discard(core, body);
    } else {
        send_body(conn, core, slot, body, &mut request.sent).await;
    }
}

/// A request in progress. When it goes, whether its work finished or the stream was reset
/// on the way, its exchange goes back to the pool, and a request whose response head is
/// out is logged with the body bytes sent.
struct Request<'a> {
    core: &'a Core,
    snap: &'a CoreSnapshot,
    ex: Option<Box<Exchange>>,
    /// Set once the response head is queued: the access log record and the status.
    answered: Option<(Option<Started>, Status)>,
    /// Body bytes queued for the client.
    sent: u64,
}

impl Drop for Request<'_> {
    fn drop(&mut self) {
        let Some(ex) = self.ex.take() else {
            return;
        };
        if let Some((Some(log), status)) = self.answered.take() {
            observe::finish(self.core, self.snap, &ex, log, status, self.sent);
        }
        self.core.exchanges.put(ex);
    }
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

/// Sends a response body as DATA frames. The next chunk is read only once the previous one
/// is queued, which waits for the client's windows and for room in the outbox, so an event
/// stream's events go out as they arrive and a slow client slows the origin down. `sent`
/// counts the bytes queued.
async fn send_body(conn: &Conn, core: &Core, slot: u32, mut body: Body, sent: &mut u64) {
    loop {
        let (chunk, last) = match body.next_chunk(core).await {
            // A body of known length ends with its last byte, in the frame that carries it.
            Ok(Some(chunk)) => (chunk, body.len() == Some(0)),
            Ok(None) => (Bytes::new(), true),
            Err(e) => {
                debug!("core {}: h2 response body: {e}", core.index);
                conn.engine.borrow_mut().reset(slot, Reason::Internal);
                return;
            }
        };
        let mut data = chunk;
        poll_fn(|_| {
            let before = data.len();
            let done = conn.engine.borrow_mut().send_data(slot, &mut data, last);
            *sent += (before - data.len()) as u64;
            // Without room, the engine marks the slot ready when there is some again.
            if done { Poll::Ready(()) } else { Poll::Pending }
        })
        .await;
        if last {
            discard(core, body);
            return;
        }
    }
}

/// Ends a body that will not be sent: an upstream connection goes back to its pool when the
/// body was complete.
fn discard(core: &Core, body: Body) {
    if let Body::Upstream(upstream) = body {
        upstream.finish(core);
    }
}

/// The receive half of a request stream, as a request body. It lives in the stream's work,
/// so it never outlasts the stream's slot.
pub(crate) struct H2Body<'a> {
    conn: &'a Conn,
    slot: u32,
    /// The client's content-length. The engine resets a stream whose DATA does not add up
    /// to it, so the length can frame the upstream request.
    len: Option<u64>,
}

impl H2Body<'_> {
    pub fn len(&self) -> Option<u64> {
        self.len
    }

    /// The next DATA payload; `None` at the end of the stream.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        // The engine marks the slot ready when DATA or the end of the stream arrives.
        Ok(poll_fn(|_| self.conn.engine.borrow_mut().read(self.slot)).await)
    }
}

/// Entry points for the fuzz targets; not part of the API.
#[cfg(any(test, feature = "internals"))]
pub mod harness;
