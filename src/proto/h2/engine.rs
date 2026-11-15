//! The HTTP/2 connection state machine (RFC 9113) without IO: the client's bytes go in one
//! frame at a time, the frames to write come out in an [`Outbox`], and what a frame asks of
//! the connection's driver comes back as an [`Event`].
//!
//! The driver owns the work of each stream and runs it; the engine owns everything the
//! protocol defines: stream states, both directions of flow control, SETTINGS, field blocks
//! and the limits below. A stream lives in a slot from its HEADERS until the driver has let
//! go of its work, so a slot index always names the stream the work was started for.
//!
//! A stream whose answer is complete stays known for a while ([`LINGER`] streams, oldest
//! out first): the client's frames for it were sent before it saw the answer, and are
//! judged as on any open stream, so an invalid one is still an error and a short rest of a
//! request body is taken and dropped instead of being refused.
//!
//! # Limits
//!
//! A client can make this side work or buffer only within these bounds:
//!
//! - Streams in progress: `max_streams`. A stream the client resets is cancelled before the
//!   next frame is read, so a reset frees nothing that is still running (CVE-2023-44487).
//! - Frames that cost more than they carry are paid from one budget ([`BUDGET_BURST`],
//!   refilled at [`BUDGET_PER_SECOND`]): a reset of a stream still being answered, PING and
//!   SETTINGS (each needs a reply), CONTINUATION, PRIORITY, DATA without data on a stream
//!   in progress, unknown frames, and every stream error. A connection that overdraws it
//!   ends with ENHANCE_YOUR_CALM. Frames that are dropped without a reply (on a stream that
//!   lingers or was reset from this side) cost what parsing their header costs, and are
//!   not charged.
//! - A field block: [`MAX_HEADER_LIST`] bytes on the wire across HEADERS and CONTINUATION
//!   (connection error past it), and the same decoded, counted as RFC 9113 6.5.2 does (431
//!   past it; the block is still decoded, because the compression state depends on it, but
//!   nothing more of it is stored).
//! - Request bodies buffered: the stream window per stream, the connection window in total.
//! - Output queued: a stream stops adding DATA at [`OUT_HIGH`], and the driver stops reading
//!   frames while that much is unwritten, so replies to a client that does not read are
//!   bounded by what one read can ask for.
//! - A stream that cannot send for lack of window is reset by [`Engine::reset_stalled`].

use super::frame::{self, Head, Reason};
use super::hpack::{Decoder, Encoder};
use super::wake::Ready;
use crate::msg::{Field, Fields, Known, RequestHead, Status, Version};
use bytes::Bytes;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::io::IoSlice;
use std::sync::Arc;
use std::task::Poll;

/// SETTINGS_INITIAL_WINDOW_SIZE: a 1 MiB request body arrives without a WINDOW_UPDATE wait.
pub(super) const STREAM_WINDOW: u32 = 1 << 20;
/// The connection window, shared by every stream's request body.
pub(super) const CONNECTION_WINDOW: u32 = 4 << 20;
/// SETTINGS_MAX_HEADER_LIST_SIZE: decoded names and values plus 32 bytes per field. Also the
/// most a field block may take on the wire.
pub(super) const MAX_HEADER_LIST: usize = 64 * 1024;
/// Unwritten output at which streams wait before adding DATA.
pub(super) const OUT_HIGH: usize = 64 * 1024;
/// Streams a connection may have in progress whatever the config says: the size of the
/// driver's ready set.
pub(super) const MAX_SLOTS: u32 = 4096;
/// Frames the budget covers at once, and per second after that.
pub(super) const BUDGET_BURST: u32 = 1000;
pub(super) const BUDGET_PER_SECOND: u32 = 33;

/// Both windows before the peer says otherwise (RFC 9113 6.9.2).
const DEFAULT_WINDOW: i64 = 65_535;
const MAX_WINDOW: i64 = (1 << 31) - 1;
/// DATA payloads up to this size are copied next to their frame header; larger ones are
/// written from where they are.
const INLINE_DATA: usize = 2048;
/// The smallest request DATA payload queued as a slice of the read buffer instead of a
/// copy: a slice keeps its whole buffer (16 KiB) allocated until it is read.
pub(super) const SHARE_MIN: usize = 8192;
/// Answered streams kept as they were, so the client's last frames for them are judged
/// like any other.
const LINGER: usize = 8;
/// How much of a request body is taken and dropped after its answer was complete; a longer
/// one is stopped with RST_STREAM(NO_ERROR) (RFC 9113 8.1).
const MAX_DRAIN: usize = 64 * 1024;
/// Closed streams remembered after that, to tell a frame that was on its way from a
/// protocol error.
const RECENT: usize = 16;
/// Capacity the buffers of field block decoding keep between blocks.
const SCRATCH_KEEP: usize = 4096;
/// The PING sent with the first GOAWAY of a shutdown; its ACK shows the client has read
/// that GOAWAY.
const SHUTDOWN_PING: [u8; 8] = *b"shutdown";

/// The frames to write, in order. Small pieces are gathered in one buffer; large DATA
/// payloads are kept as they are and written between the buffer's parts. What is written
/// is let go of as writing goes on, so a client that reads slowly holds no more than what
/// is still queued.
#[derive(Default)]
pub(super) struct Outbox {
    buf: Vec<u8>,
    /// How much of `buf` is written.
    buf_done: usize,
    /// Payloads that go out after the first `.0` bytes of `buf`, in order.
    cuts: VecDeque<(usize, Bytes)>,
    cut_bytes: usize,
    /// How much of the first cut is written. While it is not 0, `buf` is written up to
    /// that cut.
    cut_done: usize,
}

impl Outbox {
    /// Bytes not written yet.
    pub fn len(&self) -> usize {
        self.buf.len() - self.buf_done + self.cut_bytes - self.cut_done
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn data(&mut self, stream: u32, payload: Bytes, end_stream: bool) {
        let flags = if end_stream { frame::END_STREAM } else { 0 };
        frame::put_head(&mut self.buf, payload.len(), frame::DATA, flags, stream);
        if payload.len() <= INLINE_DATA {
            self.buf.extend_from_slice(&payload);
        } else {
            self.cut_bytes += payload.len();
            self.cuts.push_back((self.buf.len(), payload));
        }
    }

    /// The unwritten bytes as slices for one vectored write (the first of them, when there
    /// are more than `slices` holds inline).
    pub fn slices<'a>(&'a self, slices: &mut SmallVec<[IoSlice<'a>; 16]>) {
        let mut push = |piece: &'a [u8]| {
            if !piece.is_empty() && slices.len() < slices.inline_size() {
                slices.push(IoSlice::new(piece));
            }
        };
        let mut at = self.buf_done;
        let mut skip = self.cut_done;
        for (cut, payload) in &self.cuts {
            push(&self.buf[at..*cut]);
            push(&payload[std::mem::take(&mut skip)..]);
            at = *cut;
        }
        push(&self.buf[at..]);
    }

    /// Notes `n` more bytes as written, and lets go of what is written in full.
    pub fn advance(&mut self, mut n: usize) {
        while n > 0 {
            let Some((cut, payload)) = self.cuts.front() else {
                self.buf_done += n;
                break;
            };
            let before = cut - self.buf_done;
            if n < before {
                self.buf_done += n;
                break;
            }
            self.buf_done = *cut;
            n -= before;
            let left = payload.len() - self.cut_done;
            if n < left {
                self.cut_done += n;
                break;
            }
            n -= left;
            self.cut_bytes -= payload.len();
            self.cut_done = 0;
            self.cuts.pop_front();
        }
        debug_assert!(self.buf_done <= self.buf.len());
        if self.buf_done == self.buf.len() && self.cuts.is_empty() {
            self.buf.clear();
            self.buf_done = 0;
        } else if self.buf_done >= OUT_HIGH {
            // At least as many bytes were written as are moved.
            self.buf.drain(..self.buf_done);
            for (cut, _) in &mut self.cuts {
                *cut -= self.buf_done;
            }
            self.buf_done = 0;
        }
    }

    /// Bytes the queue keeps in memory, written or not.
    #[cfg(any(test, feature = "internals"))]
    pub fn held(&self) -> usize {
        self.buf.len() + self.cut_bytes
    }

    /// Gives back the memory of a burst once the queue is empty.
    fn shrink(&mut self) {
        if self.is_empty() && self.buf.capacity() > OUT_HIGH / 4 {
            self.buf = Vec::new();
            self.cuts = VecDeque::new();
        }
    }
}

struct Budget {
    tokens: u32,
    /// The second `tokens` was last refilled in.
    at: i64,
}

impl Budget {
    fn spend(&mut self, now: i64) -> Result<(), Reason> {
        if now > self.at {
            let refill = u32::try_from(now - self.at)
                .unwrap_or(u32::MAX)
                .saturating_mul(BUDGET_PER_SECOND);
            self.tokens = self.tokens.saturating_add(refill).min(BUDGET_BURST);
            self.at = now;
        }
        self.tokens = self.tokens.checked_sub(1).ok_or(Reason::EnhanceYourCalm)?;
        Ok(())
    }
}

/// The field block of the last response head that was encoded entirely from the table,
/// with what it was encoded from. A connection that answers the same way again (the same
/// file, the same origin's response) sends the block as it is.
#[derive(Default)]
struct LastHead {
    status: u16,
    length: Option<u64>,
    date: Option<[u8; 29]>,
    /// The head's fields: their bytes and the table over them.
    bytes: Vec<u8>,
    fields: Vec<Field>,
    block: Vec<u8>,
    /// The encoder's change count the block is good for.
    changes: u64,
}

/// Heads with more field bytes than this are encoded each time.
const LAST_HEAD_MAX: usize = 2048;

impl LastHead {
    fn is(
        &self,
        status: Status,
        fields: &Fields,
        length: Option<u64>,
        date: Option<&[u8]>,
    ) -> bool {
        self.status == status.code()
            && self.length == length
            && self.date.as_ref().map(|date| &date[..]) == date
            && self.bytes == fields.buf
            && self.fields.len() == fields.table.len()
            && self
                .fields
                .iter()
                .zip(&fields.table)
                .all(|(a, b)| (a.name, a.value, a.tag, a.live) == (b.name, b.value, b.tag, b.live))
    }

    fn keep(
        &mut self,
        status: Status,
        fields: &Fields,
        length: Option<u64>,
        date: Option<&[u8]>,
        block: &[u8],
        changes: u64,
    ) {
        self.status = status.code();
        self.length = length;
        self.date = date.and_then(|date| date.try_into().ok());
        self.bytes.clear();
        self.bytes.extend_from_slice(&fields.buf);
        self.fields.clear();
        self.fields.extend_from_slice(&fields.table);
        self.block.clear();
        self.block.extend_from_slice(block);
        self.changes = changes;
    }
}

struct Stream {
    /// 0 while the slot is free or its stream has closed.
    id: u32,
    send_window: i64,
    recv_window: i64,
    /// Body bytes the work took (and padding) not yet given back with WINDOW_UPDATE.
    recv_unacked: u32,
    /// Request body pieces the work has not taken: whole payloads, then `recv_small`.
    recv: VecDeque<Bytes>,
    /// The small payloads that arrived after the last piece of `recv`, joined.
    recv_small: Vec<u8>,
    /// What is left of the declared content-length.
    remaining: Option<u64>,
    /// The client ended the stream.
    recv_end: bool,
    /// END_STREAM is queued.
    send_end: bool,
    /// In the queue for the connection's send capacity.
    queued: bool,
    /// The second since which its DATA has waited for window.
    stalled_at: Option<i64>,
    /// Its work is over and its answer complete: it lingers.
    answered: bool,
    /// Request body bytes dropped since.
    drained: usize,
}

/// How a request starts.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Begin {
    /// Answer with this status without routing the request.
    pub preset: Option<Status>,
    /// The declared content-length.
    pub length: Option<u64>,
    /// The request has no body.
    pub end_stream: bool,
}

/// What a frame asks of the driver.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    None,
    /// The stream in `slot` is over: drop its work, then [`Engine::release`] the slot.
    Cancel {
        slot: u32,
    },
}

/// What a field block was.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Opened {
    /// A request: run it as the work of `slot`, with the head the block was decoded into.
    Request { slot: u32, begin: Begin },
    /// Trailers, or a request that was refused.
    Not(Event),
}

/// A HEADERS frame (with its CONTINUATION frames) whose field block is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Block {
    stream: u32,
    end_stream: bool,
    /// The frame's priority fields name the stream itself (RFC 9113 5.3.1).
    self_dependent: bool,
}

/// The result of looking at the front of the receive buffer.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Step {
    /// No whole frame yet.
    More,
    /// A frame of `len` bytes was handled.
    Done { len: usize, event: Event },
    /// A frame of `len` bytes completes a field block: pass it to [`Engine::open`], with
    /// the range `fragment` of the buffer when the block is that one frame.
    Block {
        len: usize,
        block: Block,
        fragment: Option<(usize, usize)>,
    },
    /// A DATA frame of `len` bytes whose data, `start..end` of the buffer, goes to
    /// [`Engine::deliver`].
    Data {
        len: usize,
        slot: u32,
        start: usize,
        end: usize,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shutdown {
    No,
    /// GOAWAY with the largest stream id is out; streams are still accepted until the client
    /// has seen it.
    Announced,
    /// GOAWAY with the last stream id is out; later streams are ignored.
    Final,
}

pub(super) struct Engine {
    pub out: Outbox,
    ready: Arc<Ready>,
    max_streams: u32,
    max_fields: u32,
    /// Octets of the client's preface not seen yet.
    preface: bool,
    /// The client's first SETTINGS arrived.
    settings_seen: bool,

    streams: Vec<Stream>,
    free: Vec<u32>,
    /// `(id, slot)` of the streams in progress and of those that linger, ascending by id.
    open: Vec<(u32, u32)>,
    /// Streams in progress.
    active: usize,
    /// Slots of the answered streams that linger, oldest first.
    lingering: VecDeque<u32>,
    /// The highest stream id the client has used.
    last_id: u32,
    /// Streams closed lately, and whether frames still arriving on them are expected
    /// (this side reset them) or an error (the client ended or reset them).
    recent: [(u32, bool); RECENT],
    recent_next: usize,

    decoder: Decoder,
    encoder: Encoder,
    last_head: LastHead,
    /// The field block in progress across CONTINUATION frames.
    continued: Option<Block>,
    block: Vec<u8>,
    /// Pseudo-header values, then joined cookies, of the block being decoded.
    stage: Vec<u8>,
    cookies: Vec<u8>,

    send_window: i64,
    /// The client's SETTINGS_INITIAL_WINDOW_SIZE.
    peer_window: i64,
    recv_window: i64,
    recv_unacked: u32,
    /// Slots waiting for connection window or room in the outbox, first come first served.
    waiting: VecDeque<u32>,
    stalled: u32,

    shutdown: Shutdown,
    /// The client sent GOAWAY.
    peer_left: bool,
    budget: Budget,
    /// Unix seconds, set by the driver from the core's clock.
    now: i64,
}

impl Engine {
    /// A connection that has sent nothing but this side's preface: SETTINGS and the
    /// connection window.
    pub fn new(ready: Arc<Ready>, max_streams: u32, max_fields: u16, now: i64) -> Engine {
        let max_streams = max_streams.min(MAX_SLOTS);
        let mut out = Outbox::default();
        frame::put_settings(
            &mut out.buf,
            &[
                (frame::SETTINGS_MAX_CONCURRENT_STREAMS, max_streams),
                (frame::SETTINGS_INITIAL_WINDOW_SIZE, STREAM_WINDOW),
                (frame::SETTINGS_MAX_HEADER_LIST_SIZE, MAX_HEADER_LIST as u32),
                (frame::SETTINGS_NO_RFC7540_PRIORITIES, 1),
            ],
        );
        frame::put_window_update(&mut out.buf, 0, CONNECTION_WINDOW - DEFAULT_WINDOW as u32);
        Engine {
            out,
            ready,
            max_streams,
            max_fields: max_fields.into(),
            preface: true,
            settings_seen: false,
            streams: Vec::new(),
            free: Vec::new(),
            open: Vec::new(),
            active: 0,
            lingering: VecDeque::new(),
            last_id: 0,
            recent: [(0, false); RECENT],
            recent_next: 0,
            decoder: Decoder::new(),
            encoder: Encoder::new(),
            last_head: LastHead::default(),
            continued: None,
            block: Vec::new(),
            stage: Vec::new(),
            cookies: Vec::new(),
            send_window: DEFAULT_WINDOW,
            peer_window: DEFAULT_WINDOW,
            recv_window: CONNECTION_WINDOW.into(),
            recv_unacked: 0,
            waiting: VecDeque::new(),
            stalled: 0,
            shutdown: Shutdown::No,
            peer_left: false,
            budget: Budget {
                tokens: BUDGET_BURST,
                at: now,
            },
            now,
        }
    }

    pub fn set_now(&mut self, now: i64) {
        self.now = now;
    }

    /// The state of the response encoder's table (see `hpack`), for checking that a client
    /// that decoded every block so far is in step with it.
    #[cfg(any(test, feature = "internals"))]
    pub fn encoder_table(&self) -> (usize, usize, usize) {
        self.encoder.table_state()
    }

    /// How many slots a connection that admits `max_streams` streams uses at most: its
    /// streams in progress, those that linger, and one being let go of.
    pub fn slots(max_streams: u32) -> u32 {
        max_streams.min(MAX_SLOTS) + LINGER as u32 + 1
    }

    /// Streams in progress.
    pub fn streams(&self) -> usize {
        self.active
    }

    /// Whether the client's preface and first SETTINGS are still to come.
    pub fn starting(&self) -> bool {
        !self.settings_seen
    }

    /// Whether a field block is waiting for its CONTINUATION frames.
    pub fn in_block(&self) -> bool {
        self.continued.is_some()
    }

    /// Whether the connection has nothing left to do: a side said it is leaving and no
    /// stream is in progress.
    pub fn finished(&self) -> bool {
        (self.shutdown == Shutdown::Final || self.peer_left) && self.active == 0
    }

    /// Whether a shutdown waits for the client to acknowledge its first GOAWAY.
    pub fn shutdown_announced(&self) -> bool {
        self.shutdown == Shutdown::Announced
    }

    /// Whether the driver should stop reading frames until output has been written.
    pub fn congested(&self) -> bool {
        self.out.len() >= OUT_HIGH
    }

    /// Looks at the front of the receive buffer `rx`. The caller drops the bytes of the
    /// frame a step names once it has followed the step.
    pub fn step(&mut self, rx: &[u8]) -> Result<Step, Reason> {
        if self.preface {
            let have = rx.len().min(frame::PREFACE.len());
            if rx[..have] != frame::PREFACE[..have] {
                return Err(Reason::Protocol);
            }
            if have < frame::PREFACE.len() {
                return Ok(Step::More);
            }
            self.preface = false;
            return Ok(Step::Done {
                len: have,
                event: Event::None,
            });
        }
        let Some(head) = Head::parse(rx) else {
            return Ok(Step::More);
        };
        // Checked on the header alone: an oversized frame is never buffered.
        if head.len > frame::MAX_FRAME {
            return Err(Reason::FrameSize);
        }
        if !self.settings_seen && (head.kind != frame::SETTINGS || head.has(frame::ACK)) {
            return Err(Reason::Protocol);
        }
        if let Some(block) = self.continued
            && (head.kind != frame::CONTINUATION || head.stream != block.stream)
        {
            return Err(Reason::Protocol);
        }
        let len = frame::HEADER_LEN + head.len;
        let Some(payload) = rx.get(frame::HEADER_LEN..len) else {
            return Ok(Step::More);
        };
        let event = match head.kind {
            frame::DATA => return self.data(head, payload),
            frame::HEADERS => return self.headers(head, payload),
            frame::CONTINUATION => return self.continuation(head, payload),
            frame::PRIORITY => self.priority(head, payload)?,
            frame::RST_STREAM => self.rst_stream(head, payload)?,
            frame::SETTINGS => self.settings(head, payload)?,
            frame::PING => self.ping(head, payload)?,
            frame::GOAWAY => self.goaway(head, payload)?,
            frame::WINDOW_UPDATE => self.window_update(head, payload)?,
            // A client cannot push (RFC 9113 8.4).
            frame::PUSH_PROMISE => return Err(Reason::Protocol),
            // Unknown types are ignored (RFC 9113 4.1).
            _ => {
                self.budget.spend(self.now)?;
                Event::None
            }
        };
        Ok(Step::Done { len, event })
    }

    fn slot_of(&self, id: u32) -> Option<u32> {
        let at = self.open.binary_search_by_key(&id, |&(id, _)| id).ok()?;
        Some(self.open[at].1)
    }

    /// Whether `id` names a stream the client has not opened yet (RFC 9113 5.1.1). Streams a
    /// server would open (even ids) are never opened here.
    fn idle(&self, id: u32) -> bool {
        id % 2 == 0 || id > self.last_id
    }

    /// Whether `id` is a stream the client opened after the last one the final GOAWAY
    /// named: its frames are ignored (RFC 9113 6.8), and `last_id` stays what was named.
    fn after_goaway(&self, id: u32) -> bool {
        self.shutdown == Shutdown::Final && id % 2 == 1 && id > self.last_id
    }

    /// For a closed stream remembered: whether frames on it are still expected.
    fn recent(&self, id: u32) -> Option<bool> {
        self.recent
            .iter()
            .find(|&&(recent, _)| recent == id)
            .map(|&(_, expected)| expected)
    }

    fn remember(&mut self, id: u32, frames_expected: bool) {
        self.recent[self.recent_next] = (id, frames_expected);
        self.recent_next = (self.recent_next + 1) % RECENT;
    }

    /// Ends the stream in `slot`: its unread body goes back to the connection window. The
    /// slot of a stream in progress stays taken until [`Engine::release`]; that of a
    /// lingering one is free. Returns whether the stream was in progress.
    fn close(&mut self, slot: u32, frames_expected: bool) -> bool {
        let stream = &mut self.streams[slot as usize];
        let id = std::mem::take(&mut stream.id);
        let in_progress = !std::mem::take(&mut stream.answered);
        let small = std::mem::take(&mut stream.recv_small).len();
        let unread = small
            + stream
                .recv
                .drain(..)
                .map(|piece| piece.len())
                .sum::<usize>();
        if stream.stalled_at.take().is_some() {
            self.stalled -= 1;
        }
        if std::mem::take(&mut stream.queued) {
            self.waiting.retain(|&waiting| waiting != slot);
        }
        if let Ok(at) = self.open.binary_search_by_key(&id, |&(id, _)| id) {
            self.open.remove(at);
        }
        if in_progress {
            self.active -= 1;
        } else {
            self.lingering.retain(|&lingering| lingering != slot);
            self.free.push(slot);
        }
        self.remember(id, frames_expected);
        self.credit(unread);
        // If this stream had been given the connection's capacity and not used it yet,
        // the next one in line gets it.
        self.grant();
        in_progress
    }

    /// Lets go of a lingering stream. One whose request never ended is told to stop
    /// sending it (RFC 9113 8.1); what was on its way is then expected.
    fn forget(&mut self, slot: u32) {
        let stream = &self.streams[slot as usize];
        let open = !stream.recv_end;
        if open {
            frame::put_rst_stream(&mut self.out.buf, stream.id, Reason::NoError);
        }
        self.close(slot, open);
    }

    /// Gives `n` received bytes back to the connection window, in updates of half a window.
    fn credit(&mut self, n: usize) {
        self.recv_unacked += n as u32;
        if self.recv_unacked >= CONNECTION_WINDOW / 2 {
            frame::put_window_update(&mut self.out.buf, 0, self.recv_unacked);
            self.recv_window += i64::from(self.recv_unacked);
            self.recv_unacked = 0;
        }
    }

    /// A stream error (RFC 9113 5.4.2): RST_STREAM, and the stream's work is cancelled if it
    /// has any.
    fn stream_error(&mut self, id: u32, reason: Reason) -> Result<Event, Reason> {
        self.budget.spend(self.now)?;
        frame::put_rst_stream(&mut self.out.buf, id, reason);
        match self.slot_of(id) {
            Some(slot) if self.close(slot, true) => Ok(Event::Cancel { slot }),
            Some(_) => Ok(Event::None),
            None => {
                self.remember(id, true);
                Ok(Event::None)
            }
        }
    }

    fn data(&mut self, head: Head, payload: &[u8]) -> Result<Step, Reason> {
        if head.stream == 0 {
            return Err(Reason::Protocol);
        }
        let (start, end) = frame::unpad(head, payload)?;
        let len = frame::HEADER_LEN + head.len;
        // The whole payload counts against the windows, padding included (RFC 9113 6.1).
        self.recv_window -= head.len as i64;
        if self.recv_window < 0 {
            return Err(Reason::FlowControl);
        }
        let done = |event| -> Result<Step, Reason> { Ok(Step::Done { len, event }) };
        let Some(slot) = self.slot_of(head.stream) else {
            self.credit(head.len);
            if self.after_goaway(head.stream) {
                return done(Event::None);
            }
            if self.idle(head.stream) {
                return Err(Reason::Protocol);
            }
            if self.recent(head.stream) == Some(true) {
                return done(Event::None);
            }
            return done(self.stream_error(head.stream, Reason::StreamClosed)?);
        };
        let data = end - start;
        let end_stream = head.has(frame::END_STREAM);
        let stream = &mut self.streams[slot as usize];
        // A lingering stream's data is dropped as it comes, so its window never fills.
        if !stream.answered {
            stream.recv_window -= head.len as i64;
        }
        let fault = if stream.recv_end {
            Some(Reason::StreamClosed)
        } else if stream.recv_window < 0 {
            Some(Reason::FlowControl)
        } else {
            // The data has to add up to the declared content-length (RFC 9113 8.1.1).
            match &mut stream.remaining {
                Some(left) if data as u64 > *left => Some(Reason::Protocol),
                Some(left) => {
                    *left -= data as u64;
                    (end_stream && *left != 0).then_some(Reason::Protocol)
                }
                None => None,
            }
        };
        if let Some(reason) = fault {
            self.credit(head.len);
            return done(self.stream_error(head.stream, reason)?);
        }
        stream.recv_end = end_stream;
        if stream.answered {
            stream.drained += head.len;
            let over = stream.drained > MAX_DRAIN;
            self.credit(head.len);
            if over {
                self.forget(slot);
            }
            return done(Event::None);
        }
        stream.recv_unacked += (head.len - data) as u32;
        self.credit(head.len - data);
        if data == 0 {
            if end_stream {
                self.ready.mark(slot);
            } else {
                self.budget.spend(self.now)?;
            }
            return done(Event::None);
        }
        Ok(Step::Data {
            len,
            slot,
            start: frame::HEADER_LEN + start,
            end: frame::HEADER_LEN + end,
        })
    }

    /// Queues the data of a [`Step::Data`] for the stream's work, as a piece of its own.
    /// `data` keeps the buffer it was read into alive, so this is for payloads that fill a
    /// good part of one ([`SHARE_MIN`]); the others go to [`Engine::deliver_copy`].
    pub fn deliver(&mut self, slot: u32, data: Bytes) {
        let stream = &mut self.streams[slot as usize];
        if !stream.recv_small.is_empty() {
            let small = std::mem::take(&mut stream.recv_small);
            stream.recv.push_back(small.into());
        }
        stream.recv.push_back(data);
        self.ready.mark(slot);
    }

    /// Queues the data of a [`Step::Data`] by copying it behind what is queued, so a body
    /// sent in many small frames takes the memory of its bytes, not of its frames.
    pub fn deliver_copy(&mut self, slot: u32, data: &[u8]) {
        self.streams[slot as usize]
            .recv_small
            .extend_from_slice(data);
        self.ready.mark(slot);
    }

    fn headers(&mut self, head: Head, payload: &[u8]) -> Result<Step, Reason> {
        if head.stream == 0 {
            return Err(Reason::Protocol);
        }
        let (mut start, end) = frame::unpad(head, payload)?;
        let mut self_dependent = false;
        if head.has(frame::PRIORITY_FLAG) {
            let fields = payload.get(start..start + 5).ok_or(Reason::FrameSize)?;
            if start + 5 > end {
                return Err(Reason::FrameSize);
            }
            self_dependent = frame::u32_at(fields) & frame::MAX_STREAM_ID == head.stream;
            start += 5;
        }
        let block = Block {
            stream: head.stream,
            end_stream: head.has(frame::END_STREAM),
            self_dependent,
        };
        let len = frame::HEADER_LEN + head.len;
        if head.has(frame::END_HEADERS) {
            return Ok(Step::Block {
                len,
                block,
                fragment: Some((frame::HEADER_LEN + start, frame::HEADER_LEN + end)),
            });
        }
        self.block.clear();
        self.block.extend_from_slice(&payload[start..end]);
        self.continued = Some(block);
        Ok(Step::Done {
            len,
            event: Event::None,
        })
    }

    fn continuation(&mut self, head: Head, payload: &[u8]) -> Result<Step, Reason> {
        let Some(block) = self.continued else {
            return Err(Reason::Protocol);
        };
        // However the block is cut into frames, it costs the client one token per frame
        // and stays within the size a field block may have.
        self.budget.spend(self.now)?;
        if self.block.len() + payload.len() > MAX_HEADER_LIST {
            return Err(Reason::EnhanceYourCalm);
        }
        self.block.extend_from_slice(payload);
        let len = frame::HEADER_LEN + head.len;
        if !head.has(frame::END_HEADERS) {
            return Ok(Step::Done {
                len,
                event: Event::None,
            });
        }
        self.continued = None;
        Ok(Step::Block {
            len,
            block,
            fragment: None,
        })
    }

    /// Decodes a complete field block. For a new stream, the request's head is built in
    /// `request`. `fragment` is the block when it arrived in one frame.
    pub fn open(
        &mut self,
        block: Block,
        fragment: Option<&[u8]>,
        request: &mut RequestHead,
    ) -> Result<Opened, Reason> {
        // A block that needed CONTINUATION is rare and large: its buffer is not kept.
        let held = std::mem::take(&mut self.block);
        let opened = self.open_block(block, fragment.unwrap_or(&held), request);
        // Nor are the buffers a large block grew, so a connection's memory follows what
        // its requests usually need.
        self.decoder.trim(SCRATCH_KEEP);
        for scratch in [&mut self.stage, &mut self.cookies] {
            if scratch.capacity() > SCRATCH_KEEP {
                drop(std::mem::take(scratch));
            }
        }
        opened
    }

    fn open_block(
        &mut self,
        block: Block,
        bytes: &[u8],
        request: &mut RequestHead,
    ) -> Result<Opened, Reason> {
        let id = block.stream;
        if let Some(slot) = self.slot_of(id) {
            return self.trailers(slot, block, bytes).map(Opened::Not);
        }
        if id % 2 == 0 {
            return Err(Reason::Protocol);
        }
        // The block is decoded whatever becomes of the stream: the compression state of
        // every later block depends on it.
        if self.after_goaway(id) {
            return self.discard(bytes).map(|()| Opened::Not(Event::None));
        }
        if id <= self.last_id {
            // A closed stream (RFC 9113 5.1): fine when the frame crossed this side's reset,
            // an error when the client had ended the stream itself.
            return match self.recent(id) {
                Some(true) => self.discard(bytes).map(|()| Opened::Not(Event::None)),
                Some(false) => Err(Reason::StreamClosed),
                None => Err(Reason::Protocol),
            };
        }
        self.last_id = id;
        if block.self_dependent {
            self.discard(bytes)?;
            return self.stream_error(id, Reason::Protocol).map(Opened::Not);
        }
        if self.active >= self.max_streams as usize {
            self.discard(bytes)?;
            return self
                .stream_error(id, Reason::RefusedStream)
                .map(Opened::Not);
        }
        let mut builder =
            HeadBuilder::new(request, &mut self.stage, &mut self.cookies, self.max_fields);
        self.decoder
            .decode(bytes, |name, value| builder.field(name, value))
            .map_err(|_| Reason::Compression)?;
        let (preset, length) = match builder.finish() {
            Verdict::Malformed => {
                return self.stream_error(id, Reason::Protocol).map(Opened::Not);
            }
            Verdict::Respond(status) => (Some(status), None),
            Verdict::Run { length } => (None, length),
        };
        if block.end_stream && length.is_some_and(|length| length != 0) {
            return self.stream_error(id, Reason::Protocol).map(Opened::Not);
        }
        let slot = self.free.pop().unwrap_or_else(|| {
            self.streams.push(Stream {
                id: 0,
                send_window: 0,
                recv_window: 0,
                recv_unacked: 0,
                recv: VecDeque::new(),
                recv_small: Vec::new(),
                remaining: None,
                recv_end: false,
                send_end: false,
                queued: false,
                stalled_at: None,
                answered: false,
                drained: 0,
            });
            self.streams.len() as u32 - 1
        });
        let stream = &mut self.streams[slot as usize];
        stream.id = id;
        stream.send_window = self.peer_window;
        stream.recv_window = STREAM_WINDOW.into();
        stream.recv_unacked = 0;
        stream.remaining = length;
        stream.recv_end = block.end_stream;
        stream.send_end = false;
        stream.drained = 0;
        self.open.push((id, slot));
        self.active += 1;
        Ok(Opened::Request {
            slot,
            begin: Begin {
                preset,
                length,
                end_stream: block.end_stream,
            },
        })
    }

    fn discard(&mut self, block: &[u8]) -> Result<(), Reason> {
        self.decoder
            .decode(block, |_, _| {})
            .map_err(|_| Reason::Compression)
    }

    /// A field block on a stream in progress: the request's trailers, which end it. Their
    /// fields are checked and dropped, as an HTTP/1.1 origin is sent none.
    fn trailers(&mut self, slot: u32, block: Block, bytes: &[u8]) -> Result<Event, Reason> {
        // Trailers hold no pseudo-header (RFC 9113 8.1), and fields as valid as any, within
        // the size a field block may decode to. Past a fault nothing more is looked at.
        let mut malformed = false;
        let mut size = 0;
        self.decoder
            .decode(bytes, |name, value| {
                if malformed {
                    return;
                }
                size += name.len() + value.len() + 32;
                malformed = size > MAX_HEADER_LIST
                    || name.is_empty()
                    || !name.iter().all(|&b| NAME_BYTE[usize::from(b)])
                    || !clean(value);
            })
            .map_err(|_| Reason::Compression)?;
        let stream = &mut self.streams[slot as usize];
        if stream.recv_end {
            // After the client's END_STREAM: a stream error while the answer is under way
            // (half-closed), a connection error once the stream is closed (RFC 9113 5.1).
            return match stream.answered {
                true => Err(Reason::StreamClosed),
                false => self.stream_error(block.stream, Reason::StreamClosed),
            };
        }
        let short = stream.remaining.is_some_and(|left| left != 0);
        if malformed || !block.end_stream || short {
            return self.stream_error(block.stream, Reason::Protocol);
        }
        stream.recv_end = true;
        self.ready.mark(slot);
        Ok(Event::None)
    }

    fn priority(&mut self, head: Head, payload: &[u8]) -> Result<Event, Reason> {
        if head.stream == 0 {
            return Err(Reason::Protocol);
        }
        self.budget.spend(self.now)?;
        let fault = if payload.len() != 5 {
            Reason::FrameSize
        } else if frame::u32_at(payload) & frame::MAX_STREAM_ID == head.stream {
            Reason::Protocol
        } else {
            return Ok(Event::None);
        };
        // A stream error needs a stream: an idle one cannot be reset (RFC 9113 5.1), so
        // there the connection is at fault; a closed one is past caring.
        match self.slot_of(head.stream) {
            Some(_) => self.stream_error(head.stream, fault),
            None if self.idle(head.stream) && !self.after_goaway(head.stream) => Err(fault),
            None => Ok(Event::None),
        }
    }

    fn rst_stream(&mut self, head: Head, payload: &[u8]) -> Result<Event, Reason> {
        if payload.len() != 4 {
            return Err(Reason::FrameSize);
        }
        if self.after_goaway(head.stream) {
            return Ok(Event::None);
        }
        if head.stream == 0 || self.idle(head.stream) {
            return Err(Reason::Protocol);
        }
        let Some(slot) = self.slot_of(head.stream) else {
            return Ok(Event::None);
        };
        // A reset of a stream that still had an answer coming throws work away.
        if !self.streams[slot as usize].send_end {
            self.budget.spend(self.now)?;
        }
        match self.close(slot, false) {
            true => Ok(Event::Cancel { slot }),
            false => Ok(Event::None),
        }
    }

    fn settings(&mut self, head: Head, payload: &[u8]) -> Result<Event, Reason> {
        if head.stream != 0 {
            return Err(Reason::Protocol);
        }
        if head.has(frame::ACK) {
            return match payload.len() {
                0 => Ok(Event::None),
                _ => Err(Reason::FrameSize),
            };
        }
        if payload.len() % 6 != 0 {
            return Err(Reason::FrameSize);
        }
        if std::mem::replace(&mut self.settings_seen, true) {
            self.budget.spend(self.now)?;
        }
        for setting in payload.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([setting[0], setting[1]]);
            let value = frame::u32_at(&setting[2..]);
            match id {
                frame::SETTINGS_HEADER_TABLE_SIZE => self.encoder.set_limit(value),
                frame::SETTINGS_ENABLE_PUSH if value > 1 => return Err(Reason::Protocol),
                frame::SETTINGS_INITIAL_WINDOW_SIZE => self.set_peer_window(value)?,
                frame::SETTINGS_MAX_FRAME_SIZE
                    if !(frame::MAX_FRAME as u32..1 << 24).contains(&value) =>
                {
                    return Err(Reason::Protocol);
                }
                // Frames sent never exceed the smallest SETTINGS_MAX_FRAME_SIZE, nothing is
                // pushed, and no stream is opened from this side.
                _ => {}
            }
        }
        frame::put_settings_ack(&mut self.out.buf);
        Ok(Event::None)
    }

    /// A new SETTINGS_INITIAL_WINDOW_SIZE moves the window of every stream in progress by
    /// the difference (RFC 9113 6.9.2).
    fn set_peer_window(&mut self, value: u32) -> Result<(), Reason> {
        let value = i64::from(value);
        if value > MAX_WINDOW {
            return Err(Reason::FlowControl);
        }
        let delta = value - self.peer_window;
        self.peer_window = value;
        for &(_, slot) in &self.open {
            let stream = &mut self.streams[slot as usize];
            let was = stream.send_window;
            stream.send_window += delta;
            if stream.send_window > MAX_WINDOW {
                return Err(Reason::FlowControl);
            }
            if was <= 0 && stream.send_window > 0 {
                self.ready.mark(slot);
            }
        }
        Ok(())
    }

    fn ping(&mut self, head: Head, payload: &[u8]) -> Result<Event, Reason> {
        if head.stream != 0 {
            return Err(Reason::Protocol);
        }
        let opaque: &[u8; 8] = payload.try_into().map_err(|_| Reason::FrameSize)?;
        if !head.has(frame::ACK) {
            self.budget.spend(self.now)?;
            frame::put_ping(&mut self.out.buf, frame::ACK, opaque);
        } else if *opaque == SHUTDOWN_PING && self.shutdown == Shutdown::Announced {
            self.finish_shutdown();
        }
        Ok(Event::None)
    }

    fn goaway(&mut self, head: Head, payload: &[u8]) -> Result<Event, Reason> {
        if head.stream != 0 {
            return Err(Reason::Protocol);
        }
        if payload.len() < 8 {
            return Err(Reason::FrameSize);
        }
        self.peer_left = true;
        Ok(Event::None)
    }

    fn window_update(&mut self, head: Head, payload: &[u8]) -> Result<Event, Reason> {
        if payload.len() != 4 {
            return Err(Reason::FrameSize);
        }
        let increment = i64::from(frame::u32_at(payload) & frame::MAX_STREAM_ID);
        if head.stream == 0 {
            if increment == 0 {
                return Err(Reason::Protocol);
            }
            self.send_window += increment;
            if self.send_window > MAX_WINDOW {
                return Err(Reason::FlowControl);
            }
            self.grant();
            return Ok(Event::None);
        }
        let Some(slot) = self.slot_of(head.stream) else {
            return match self.idle(head.stream) && !self.after_goaway(head.stream) {
                true => Err(Reason::Protocol),
                // A closed stream's window no longer matters.
                false => Ok(Event::None),
            };
        };
        if increment == 0 {
            return self.stream_error(head.stream, Reason::Protocol);
        }
        let stream = &mut self.streams[slot as usize];
        let was = stream.send_window;
        stream.send_window += increment;
        if stream.send_window > MAX_WINDOW {
            return self.stream_error(head.stream, Reason::FlowControl);
        }
        if was <= 0 && stream.send_window > 0 {
            self.ready.mark(slot);
        }
        Ok(Event::None)
    }

    /// Whether DATA can be queued as far as the connection is concerned.
    fn has_capacity(&self) -> bool {
        self.send_window > 0 && self.out.len() < OUT_HIGH
    }

    /// Wakes the stream that has waited longest for the connection's capacity. It wakes the
    /// next one when it leaves some.
    fn grant(&mut self) {
        if self.has_capacity()
            && let Some(slot) = self.waiting.pop_front()
        {
            self.streams[slot as usize].queued = false;
            self.ready.mark(slot);
        }
    }

    /// Called by the driver when output was written, which may have made room for DATA: the
    /// stream waiting for it is marked ready.
    pub fn written(&mut self) {
        self.grant();
        self.out.shrink();
    }

    /// Queues the response head of the stream in `slot`: status, the head's end-to-end
    /// fields, then `length` as content-length and `date`, each when given. A head's own
    /// Content-Length is never sent (the body's length is `length`), nor is its Date when
    /// `date` replaces it.
    pub fn send_head(
        &mut self,
        slot: u32,
        status: Status,
        fields: &Fields,
        length: Option<u64>,
        date: Option<&[u8]>,
        end_stream: bool,
    ) {
        let stream = &mut self.streams[slot as usize];
        if stream.id == 0 {
            return;
        }
        stream.send_end = end_stream;
        let out = &mut self.out.buf;
        let start = out.len();
        out.extend_from_slice(&[0; frame::HEADER_LEN]);
        let changes = self.encoder.changes();
        if self.last_head.changes == changes
            && !self.last_head.block.is_empty()
            && self.last_head.is(status, fields, length, date)
        {
            out.extend_from_slice(&self.last_head.block);
            return frame::finish_headers(out, start, stream.id, end_stream);
        }
        self.encoder.begin(out);
        self.encoder.status(out, status.code());
        for (name, value, tag) in fields.live() {
            match tag {
                Known::ContentLength => {}
                Known::Date if date.is_some() => {}
                tag if tag.hop_by_hop() => {}
                // A cookie is for one client: no table holds it (RFC 7541 7.1.3).
                Known::Other if name == b"set-cookie" => self.encoder.sensitive(out, name, value),
                _ => self.encoder.field(out, name, value),
            }
        }
        if let Some(length) = length {
            let mut digits = [0u8; 20];
            let mut at = digits.len();
            let mut left = length;
            loop {
                at -= 1;
                digits[at] = b'0' + (left % 10) as u8;
                left /= 10;
                if left == 0 {
                    break;
                }
            }
            self.encoder.field(out, b"content-length", &digits[at..]);
        }
        if let Some(date) = date {
            self.encoder.field(out, b"date", date);
        }
        // A block that changed nothing was encoded from the table alone (but for fields
        // no table holds): the same head gets the same block until the table changes.
        if self.encoder.changes() == changes && fields.buf.len() <= LAST_HEAD_MAX {
            let block = &out[start + frame::HEADER_LEN..];
            self.last_head
                .keep(status, fields, length, date, block, changes);
        }
        frame::finish_headers(out, start, stream.id, end_stream);
    }

    /// Queues as much of `data` as the windows and the outbox take, as DATA frames of the
    /// stream in `slot`, the last one ending the stream when `end_stream`. True once all of
    /// it is queued; until then the stream's slot is marked ready when there is room again.
    pub fn send_data(&mut self, slot: u32, data: &mut Bytes, end_stream: bool) -> bool {
        let stream = &mut self.streams[slot as usize];
        if stream.id == 0 {
            data.clear();
            return true;
        }
        // Woken by its own window rather than by its turn: it queues again if it must.
        if std::mem::take(&mut stream.queued) {
            self.waiting.retain(|&waiting| waiting != slot);
        }
        let mut sent = false;
        let done = loop {
            if data.is_empty() {
                if end_stream && !stream.send_end {
                    self.out.data(stream.id, Bytes::new(), true);
                    stream.send_end = true;
                }
                break true;
            }
            let room = stream.send_window.min(self.send_window);
            if room <= 0 || self.out.len() >= OUT_HIGH {
                break false;
            }
            let n = data.len().min(frame::MAX_FRAME).min(room as usize);
            let piece = data.split_to(n);
            let last = end_stream && data.is_empty();
            self.out.data(stream.id, piece, last);
            stream.send_window -= n as i64;
            self.send_window -= n as i64;
            sent = true;
            if last {
                stream.send_end = true;
                break true;
            }
        };
        if (sent || done) && stream.stalled_at.take().is_some() {
            self.stalled -= 1;
        }
        if !done {
            let no_window = stream.send_window <= 0 || self.send_window <= 0;
            if no_window && stream.stalled_at.is_none() {
                stream.stalled_at = Some(self.now);
                self.stalled += 1;
            }
            // A stream out of its own window is woken by its WINDOW_UPDATE.
            if stream.send_window > 0 && !std::mem::replace(&mut stream.queued, true) {
                self.waiting.push_back(slot);
            }
        }
        self.grant();
        done
    }

    /// The next piece of the request body of the stream in `slot`, `None` at its end.
    /// Pending marks nothing: the slot is marked ready when DATA or the end arrives. What
    /// is handed out goes back to the client's windows, in updates of half a window, so the
    /// windows bound what is buffered for a request.
    pub fn read(&mut self, slot: u32) -> Poll<Option<Bytes>> {
        let stream = &mut self.streams[slot as usize];
        let piece = match stream.recv.pop_front() {
            Some(piece) => piece,
            None if !stream.recv_small.is_empty() => {
                Bytes::from(std::mem::take(&mut stream.recv_small))
            }
            None => {
                return match stream.recv_end || stream.id == 0 {
                    true => Poll::Ready(None),
                    false => Poll::Pending,
                };
            }
        };
        stream.recv_unacked += piece.len() as u32;
        if !stream.recv_end && stream.recv_unacked >= STREAM_WINDOW / 2 {
            frame::put_window_update(&mut self.out.buf, stream.id, stream.recv_unacked);
            stream.recv_window += i64::from(stream.recv_unacked);
            stream.recv_unacked = 0;
        }
        self.credit(piece.len());
        Poll::Ready(Some(piece))
    }

    /// Resets the stream in `slot` from its own work, which then ends.
    pub fn reset(&mut self, slot: u32, reason: Reason) {
        let id = self.streams[slot as usize].id;
        if id != 0 {
            frame::put_rst_stream(&mut self.out.buf, id, reason);
            self.close(slot, true);
        }
    }

    /// Called when the work of `slot` has ended. A stream whose answer is complete lingers;
    /// one the work left without an answer is reset.
    pub fn finish(&mut self, slot: u32) {
        let stream = &mut self.streams[slot as usize];
        if stream.id == 0 {
            // The work reset the stream itself.
            return self.free.push(slot);
        }
        if !stream.send_end {
            frame::put_rst_stream(&mut self.out.buf, stream.id, Reason::Internal);
            self.close(slot, true);
            return self.free.push(slot);
        }
        stream.answered = true;
        let small = std::mem::take(&mut stream.recv_small).len();
        let unread = small
            + stream
                .recv
                .drain(..)
                .map(|piece| piece.len())
                .sum::<usize>();
        // What the work left unread counts as dropped, like what arrives from here on.
        stream.drained = unread;
        self.active -= 1;
        self.credit(unread);
        self.lingering.push_back(slot);
        let over = unread > MAX_DRAIN;
        if over {
            self.forget(slot);
        } else if self.lingering.len() > LINGER
            && let Some(&oldest) = self.lingering.front()
        {
            self.forget(oldest);
        }
    }

    /// Frees the slot of a cancelled stream, once its work is dropped.
    pub fn release(&mut self, slot: u32) {
        debug_assert_eq!(self.streams[slot as usize].id, 0);
        self.free.push(slot);
    }

    /// The second since which the longest-stalled stream has waited for window.
    pub fn stalled_since(&self) -> Option<i64> {
        if self.stalled == 0 {
            return None;
        }
        self.open
            .iter()
            .filter_map(|&(_, slot)| self.streams[slot as usize].stalled_at)
            .min()
    }

    /// Resets the streams whose DATA has waited for window since `before` or longer: a
    /// client that grants no window must not hold a stream's upstream forever. The driver
    /// drops the work of each slot added to `cancelled` and releases the slot.
    pub fn reset_stalled(&mut self, before: i64, cancelled: &mut Vec<u32>) {
        if self.stalled == 0 {
            return;
        }
        for at in (0..self.open.len()).rev() {
            let (id, slot) = self.open[at];
            if self.streams[slot as usize]
                .stalled_at
                .is_some_and(|since| since <= before)
            {
                frame::put_rst_stream(&mut self.out.buf, id, Reason::Cancel);
                self.close(slot, true);
                cancelled.push(slot);
            }
        }
    }

    /// Starts a graceful shutdown (RFC 9113 6.8): a GOAWAY that still admits every stream,
    /// and a PING whose ACK shows the client has read it. [`Engine::finish_shutdown`]
    /// follows on that ACK, or when the driver has waited long enough.
    pub fn start_shutdown(&mut self) {
        if self.shutdown == Shutdown::No {
            frame::put_goaway(&mut self.out.buf, frame::MAX_STREAM_ID, Reason::NoError);
            frame::put_ping(&mut self.out.buf, 0, &SHUTDOWN_PING);
            self.shutdown = Shutdown::Announced;
        }
    }

    /// Sends the GOAWAY that names the last stream served. Streams opened after it are
    /// ignored; the client retries them elsewhere.
    pub fn finish_shutdown(&mut self) {
        if self.shutdown != Shutdown::Final {
            frame::put_goaway(&mut self.out.buf, self.last_id, Reason::NoError);
            self.shutdown = Shutdown::Final;
        }
    }

    /// Ends the connection for a connection error (RFC 9113 5.4.1).
    pub fn fail(&mut self, reason: Reason) {
        frame::put_goaway(&mut self.out.buf, self.last_id, reason);
        self.shutdown = Shutdown::Final;
    }
}

/// Bytes a field name may hold: token characters (RFC 9110 5.6.2) without the uppercase
/// letters, which HTTP/2 forbids in names (RFC 9113 8.2.1).
static NAME_BYTE: [bool; 256] = {
    let mut table = [false; 256];
    let mut b = 0;
    while b < 256 {
        let c = b as u8;
        table[b] = c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || matches!(
                c,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            );
        b += 1;
    }
    table
};

/// Whether a field value is free of control bytes other than a tab. HTTP/2 forbids NUL, CR
/// and LF (RFC 9113 8.2.1); the rest is what the HTTP/1.1 parser refuses, since the request
/// is forwarded as HTTP/1.1.
fn clean(value: &[u8]) -> bool {
    !value.iter().fold(false, |bad, &b| {
        bad | ((b < 0x20 && b != b'\t') | (b == 0x7f))
    })
}

/// What a request's field block amounts to.
enum Verdict {
    /// A request for the pipeline, with its declared content-length.
    Run { length: Option<u64> },
    /// A request answered with this status without being routed.
    Respond(Status),
    /// Malformed (RFC 9113 8.1.1): a stream error.
    Malformed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Accept,
    Reject(Status),
    Malformed,
}

/// Builds a request head from the fields of a block, in the order they are decoded.
struct HeadBuilder<'a> {
    request: &'a mut RequestHead,
    /// Pseudo-header values and the first Host, until the block ends.
    stage: &'a mut Vec<u8>,
    /// Cookie fields joined with `; ` into one, as HTTP/1.1 carries them (RFC 9113 8.2.3).
    cookies: &'a mut Vec<u8>,
    method: Option<(usize, usize)>,
    path: Option<(usize, usize)>,
    authority: Option<(usize, usize)>,
    host: Option<(usize, usize)>,
    scheme: bool,
    /// The request line is set: every pseudo-header has been seen.
    line: bool,
    regular: bool,
    count: u32,
    max_fields: u32,
    size: usize,
    length: Option<u64>,
    fate: Fate,
}

impl<'a> HeadBuilder<'a> {
    fn new(
        request: &'a mut RequestHead,
        stage: &'a mut Vec<u8>,
        cookies: &'a mut Vec<u8>,
        max_fields: u32,
    ) -> HeadBuilder<'a> {
        request.clear();
        stage.clear();
        cookies.clear();
        HeadBuilder {
            request,
            stage,
            cookies,
            method: None,
            path: None,
            authority: None,
            host: None,
            scheme: false,
            line: false,
            regular: false,
            count: 0,
            max_fields,
            size: 0,
            length: None,
            fate: Fate::Accept,
        }
    }

    fn reject(&mut self, status: Status) {
        if self.fate == Fate::Accept {
            self.fate = Fate::Reject(status);
        }
    }

    fn staged(&mut self, value: &[u8]) -> (usize, usize) {
        let start = self.stage.len();
        self.stage.extend_from_slice(value);
        (start, self.stage.len())
    }

    fn field(&mut self, name: &[u8], value: &[u8]) {
        // Once the request is refused, the rest of its block is decoded for the table's
        // sake only: a field costs nothing more, however large the entry it refers to.
        if self.fate != Fate::Accept {
            return;
        }
        self.size += name.len() + value.len() + 32;
        if self.size > MAX_HEADER_LIST {
            return self.reject(Status::HEADER_FIELDS_TOO_LARGE);
        }
        if !clean(value) {
            self.fate = Fate::Malformed;
            return;
        }
        if name.first() == Some(&b':') {
            return self.pseudo(name, value);
        }
        self.regular = true;
        self.count += 1;
        if self.count > self.max_fields {
            return self.reject(Status::HEADER_FIELDS_TOO_LARGE);
        }
        if name.is_empty() || !name.iter().all(|&b| NAME_BYTE[usize::from(b)]) {
            self.fate = Fate::Malformed;
            return;
        }
        match name {
            // Connection-specific fields have no place in HTTP/2 (RFC 9113 8.2.2).
            b"connection" | b"keep-alive" | b"proxy-connection" | b"transfer-encoding"
            | b"upgrade" => {
                self.fate = Fate::Malformed;
                return;
            }
            b"te" if !value.eq_ignore_ascii_case(b"trailers") => {
                self.fate = Fate::Malformed;
                return;
            }
            b"content-length" => {
                let Some(length) = parse_length(value) else {
                    self.fate = Fate::Malformed;
                    return;
                };
                match self.length.replace(length) {
                    None => {}
                    Some(first) if first == length => return,
                    Some(_) => {
                        self.fate = Fate::Malformed;
                        return;
                    }
                }
            }
            b"cookie" => {
                if !self.cookies.is_empty() {
                    self.cookies.extend_from_slice(b"; ");
                }
                self.cookies.extend_from_slice(value);
                return;
            }
            // One Host, naming an authority, as on HTTP/1.1 (RFC 9112 3.2).
            b"host" if self.host.is_some() || !authority(value) => {
                return self.reject(Status::BAD_REQUEST);
            }
            b"host" => self.host = Some(self.staged(value)),
            _ => {}
        }
        if !self.line {
            self.set_line();
        }
        if self.fate == Fate::Accept {
            self.request.push_field(name, value);
        }
    }

    fn pseudo(&mut self, name: &[u8], value: &[u8]) {
        // Pseudo-headers come before the other fields, each at most once, and a request
        // has only these four (RFC 9113 8.3).
        let seen = match name {
            b":method" => self.method.is_some(),
            b":path" => self.path.is_some(),
            b":authority" => self.authority.is_some(),
            b":scheme" => self.scheme,
            _ => true,
        };
        if self.regular || seen {
            self.fate = Fate::Malformed;
            return;
        }
        let staged = self.staged(value);
        match name {
            b":method" => self.method = Some(staged),
            b":path" => self.path = Some(staged),
            b":authority" => self.authority = Some(staged),
            _ => self.scheme = true,
        }
    }

    /// Sets the request line once the pseudo-headers are complete.
    fn set_line(&mut self) {
        self.line = true;
        if self.fate != Fate::Accept {
            return;
        }
        let Some((start, end)) = self.method else {
            self.fate = Fate::Malformed;
            return;
        };
        let method = &self.stage[start..end];
        // The method and the path become the request line an HTTP/1.1 origin reads: a
        // token and a target without a space, like the ones the HTTP/1.1 parser accepts.
        if method.is_empty() || !method.iter().all(|&b| crate::msg::is_tchar(b)) {
            self.fate = Fate::Malformed;
            return;
        }
        // CONNECT has neither scheme nor path (RFC 9113 8.5), and no tunnel is offered.
        if method == b"CONNECT" {
            return self.reject(Status::BAD_REQUEST);
        }
        let path = match self.path {
            Some((start, end)) if start < end && self.scheme => &self.stage[start..end],
            _ => {
                self.fate = Fate::Malformed;
                return;
            }
        };
        let origin_form = path.first() == Some(&b'/') || path == b"*";
        let visible = path.iter().all(|b| b.is_ascii_graphic());
        if !origin_form || !visible || self.request.set_line(method, path, Version::H2).is_err() {
            self.reject(Status::BAD_REQUEST);
        }
    }

    fn finish(mut self) -> Verdict {
        if !self.line {
            self.set_line();
        }
        match self.fate {
            Fate::Malformed => return Verdict::Malformed,
            Fate::Reject(status) => return Verdict::Respond(status),
            Fate::Accept => {}
        }
        if !self.cookies.is_empty() {
            self.request.push_field(b"cookie", self.cookies);
        }
        // The routing host is `:authority`, else Host. A request with neither, or whose
        // Host names another authority, is refused; without a Host field one is added, so
        // an HTTP/1.1 origin gets it.
        let authority = self
            .authority
            .filter(|(start, end)| start < end)
            .map(|(start, end)| &self.stage[start..end]);
        if authority.is_some_and(|authority| !self::authority(authority)) {
            return Verdict::Respond(Status::BAD_REQUEST);
        }
        let host = self.host.map(|(start, end)| &self.stage[start..end]);
        match (authority, host) {
            (Some(authority), Some(host)) if !authority.eq_ignore_ascii_case(host) => {
                return Verdict::Respond(Status::BAD_REQUEST);
            }
            (Some(authority), None) => self.request.push_field(b"host", authority),
            (None, None) => return Verdict::Respond(Status::BAD_REQUEST),
            _ => {}
        }
        self.request
            .set_host(authority.or(host).unwrap_or_default());
        Verdict::Run {
            length: self.length,
        }
    }
}

/// Whether `value` consists of RFC 3986 authority characters (reg-name, IP literal, port),
/// as the HTTP/1.1 parser requires of a Host.
fn authority(value: &[u8]) -> bool {
    value
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:[]%".contains(&b))
}

/// A content-length: decimal digits only, within 64 bits.
fn parse_length(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0u64, |length, &b| {
        b.is_ascii_digit()
            .then(|| length.checked_mul(10)?.checked_add(u64::from(b - b'0')))?
    })
}
