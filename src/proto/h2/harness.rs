//! The protocol engine and the field block codec driven without a socket, for the fuzz
//! targets and the tests: [`Session`] does what the connection's driver does with the
//! engine's steps, and [`Responder`] stands in for the work of the streams.

use super::engine::{Begin, Engine, Event, OUT_HIGH, Opened, SHARE_MIN, Step};
use super::frame::{self, Reason};
use super::hpack::{Decoder, Encoder};
use super::wake::Ready;
use crate::msg::{Fields, RequestHead, Status};
use bytes::{Buf, Bytes, BytesMut};
use smallvec::SmallVec;
use std::sync::Arc;
use std::task::Poll;

/// What the frames of one read asked for.
#[derive(Debug)]
pub(super) enum Happened {
    Request {
        slot: u32,
        begin: Begin,
        head: Box<RequestHead>,
    },
    Cancel {
        slot: u32,
    },
}

pub(super) struct Session {
    pub engine: Engine,
    pub ready: Arc<Ready>,
    rx: BytesMut,
}

impl Session {
    pub fn new(max_streams: u32, max_fields: u16) -> Session {
        let ready = Ready::new(Engine::slots(max_streams));
        Session {
            engine: Engine::new(ready.clone(), max_streams, max_fields, 0),
            ready,
            rx: BytesMut::new(),
        }
    }

    /// Takes `bytes` as one read and handles the frames they complete, as far as the
    /// outbox has room.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<Happened>, Reason> {
        self.rx.extend_from_slice(bytes);
        let mut happened = Vec::new();
        while !self.engine.congested() {
            match self.engine.step(&self.rx)? {
                Step::More => break,
                Step::Done { len, event } => {
                    self.rx.advance(len);
                    self.follow(event, &mut happened);
                }
                Step::Data {
                    len,
                    slot,
                    start,
                    end,
                } if end - start >= SHARE_MIN => {
                    self.rx.advance(start);
                    let data = self.rx.split_to(end - start).freeze();
                    self.rx.advance(len - end);
                    self.engine.deliver(slot, data);
                }
                Step::Data {
                    len,
                    slot,
                    start,
                    end,
                } => {
                    self.engine.deliver_copy(slot, &self.rx[start..end]);
                    self.rx.advance(len);
                }
                Step::Block {
                    len,
                    block,
                    fragment,
                } => {
                    let mut head = Box::new(RequestHead::new());
                    let fragment = fragment.map(|(start, end)| &self.rx[start..end]);
                    let opened = self.engine.open(block, fragment, &mut head);
                    self.rx.advance(len);
                    match opened? {
                        Opened::Request { slot, begin } => {
                            happened.push(Happened::Request { slot, begin, head });
                        }
                        Opened::Not(event) => self.follow(event, &mut happened),
                    }
                }
            }
        }
        Ok(happened)
    }

    fn follow(&mut self, event: Event, happened: &mut Vec<Happened>) {
        if let Event::Cancel { slot } = event {
            self.engine.release(slot);
            happened.push(Happened::Cancel { slot });
        }
    }

    /// Takes the outbox's bytes, as a write that the transport accepts whole.
    pub fn written(&mut self) -> Vec<u8> {
        self.written_up_to(usize::MAX)
    }

    /// Takes at most `max` of the outbox's bytes, as a transport with little room does.
    pub fn written_up_to(&mut self, max: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        while !self.engine.out.is_empty() && bytes.len() < max {
            let mut slices = SmallVec::new();
            self.engine.out.slices(&mut slices);
            let before = bytes.len();
            for slice in &slices {
                let room = max - bytes.len();
                bytes.extend_from_slice(&slice[..slice.len().min(room)]);
            }
            drop(slices);
            self.engine.out.advance(bytes.len() - before);
        }
        if !bytes.is_empty() {
            self.engine.written();
        }
        bytes
    }
}

/// Cuts written bytes into frames. Panics on bytes that are not whole frames within the
/// frame size this server sends.
pub(super) fn frames(mut bytes: &[u8]) -> Vec<(frame::Head, Vec<u8>)> {
    let mut frames = Vec::new();
    while !bytes.is_empty() {
        let head = frame::Head::parse(bytes).expect("a whole frame header");
        assert!(head.len <= frame::MAX_FRAME, "{head:?}");
        let end = frame::HEADER_LEN + head.len;
        frames.push((head, bytes[frame::HEADER_LEN..end].to_vec()));
        bytes = &bytes[end..];
    }
    frames
}

/// One stream's stand-in work: reads the request body to its end, then answers with a
/// head and `body` bytes. Requests for the same path get the same head, as the requests
/// for one file do.
struct Work {
    reading: bool,
    head_sent: bool,
    body: Bytes,
    status: Status,
}

/// The fields of a response head, as a client should decode them.
type Head = Vec<(Vec<u8>, Vec<u8>)>;

/// The Date every stand-in response carries.
const DATE: &[u8; 29] = b"Thu, 01 Jan 1970 00:00:00 GMT";

/// Answers every request of a [`Session`], as the streams' work would.
#[derive(Default)]
pub(super) struct Responder {
    work: Vec<Option<Work>>,
    fields: Fields,
    /// The heads sent and not yet checked against what was written, oldest first, each
    /// with the state of the encoder's table once it was encoded.
    pub sent: std::collections::VecDeque<(Head, (usize, usize, usize))>,
}

impl Responder {
    pub fn request(&mut self, slot: u32, begin: &Begin, head: &RequestHead) {
        let index = slot as usize;
        if self.work.len() <= index {
            self.work.resize_with(index + 1, || None);
        }
        assert!(self.work[index].is_none(), "slot {slot} is in use");
        // The path's length picks the body's size, so inputs reach every way a body is
        // framed: none, inline, kept as is, larger than a window.
        let size = match head.path().as_bytes().len() {
            0 | 1 => 0,
            n @ 2..=4 => n * 300,
            n => n * 9000,
        };
        self.work[index] = Some(Work {
            reading: begin.preset.is_none() && !begin.end_stream,
            head_sent: false,
            body: Bytes::from(vec![b'x'; size]),
            status: begin.preset.unwrap_or(Status::OK),
        });
    }

    /// Drops the work of every stream, as the driver does when the connection ends.
    pub fn stop(&mut self) {
        self.work.clear();
    }

    pub fn cancel(&mut self, slot: u32) {
        let work = self.work.get_mut(slot as usize).and_then(Option::take);
        assert!(work.is_some(), "slot {slot} was cancelled without work");
    }

    /// Runs the work of every slot marked ready (all of them when `all`), until none is.
    pub fn run(&mut self, session: &mut Session, all: bool) {
        if all {
            for slot in 0..self.work.len() as u32 {
                session.ready.mark(slot);
            }
        }
        let mut marked = Vec::new();
        while session.ready.take(|slot| marked.push(slot)) {
            for slot in marked.drain(..) {
                self.resume(session, slot);
            }
        }
    }

    fn resume(&mut self, session: &mut Session, slot: u32) {
        let Some(work) = self.work.get_mut(slot as usize).and_then(Option::as_mut) else {
            return;
        };
        let engine = &mut session.engine;
        while work.reading {
            match engine.read(slot) {
                Poll::Ready(Some(_)) => {}
                Poll::Ready(None) => work.reading = false,
                Poll::Pending => return,
            }
        }
        if !work.head_sent {
            self.fields.clear();
            self.fields.push(b"content-type", b"text/plain");
            self.fields.push(b"set-cookie", b"id=1");
            let length = work.body.len() as u64;
            let empty = work.body.is_empty();
            let status = work.status;
            engine.send_head(slot, status, &self.fields, Some(length), Some(DATE), empty);
            work.head_sent = true;
            let field = |name: &str, value: String| (name.as_bytes().to_vec(), value.into_bytes());
            let head = vec![
                field(":status", status.code().to_string()),
                field("content-type", "text/plain".to_owned()),
                field("set-cookie", "id=1".to_owned()),
                field("content-length", length.to_string()),
                (b"date".to_vec(), DATE.to_vec()),
            ];
            self.sent.push_back((head, engine.encoder_table()));
        }
        if work.body.is_empty() || engine.send_data(slot, &mut work.body, true) {
            self.work[slot as usize] = None;
            engine.finish(slot);
        }
    }
}

/// Fuzz entry: a client's bytes after a valid preface, cut into reads.
///
/// The first byte chooses how the client reads what the server writes (all of it after
/// every read, a little of it, or nothing until the end); each read is one length byte
/// and that many bytes. Whatever the bytes are, the engine must not panic, must keep its
/// output within what a client that does not read can make it queue, must write only whole
/// frames, and a client must decode from its field blocks exactly the heads that were
/// sent, in the order they were sent, with its compression table in step with the server's
/// after each. After every read the streams in progress are within the limit and the
/// windows within their bounds (see [`Engine::check_windows`]).
pub fn frames_input(data: &[u8]) {
    let Some((&options, mut data)) = data.split_first() else {
        return;
    };
    let reads_output = options & 1 == 0;
    let takes = match options & 2 {
        0 => usize::MAX,
        _ => 1 + usize::from(options >> 2) * 40,
    };
    const MAX_STREAMS: u32 = 4;
    let mut session = Session::new(MAX_STREAMS, 16);
    let mut responder = Responder::default();
    let mut client = Decoder::new();
    let mut wire = Vec::new();
    let mut block = Vec::new();
    let mut check = |session: &mut Session, responder: &mut Responder, takes: usize| {
        wire.extend_from_slice(&session.written_up_to(takes));
        let mut at = 0;
        while let Some(head) = frame::Head::parse(&wire[at..]) {
            assert!(head.len <= frame::MAX_FRAME, "{head:?}");
            let start = at + frame::HEADER_LEN;
            let Some(payload) = wire.get(start..start + head.len) else {
                break;
            };
            at = start + head.len;
            match head.kind {
                frame::HEADERS | frame::CONTINUATION => {
                    block.extend_from_slice(payload);
                    if head.has(frame::END_HEADERS) {
                        let mut decoded = Head::new();
                        client
                            .decode(&block, |name, value| {
                                decoded.push((name.to_vec(), value.to_vec()));
                            })
                            .expect("a response block decodes");
                        let (sent, table) = responder.sent.pop_front().expect("a head was sent");
                        assert_eq!(decoded, sent);
                        assert_eq!(client.table_state(), table, "the client's table is in step");
                        block.clear();
                    }
                }
                _ => assert!(block.is_empty(), "a block is not interleaved"),
            }
        }
        wire.drain(..at);
    };

    let mut preface = frame::PREFACE.to_vec();
    frame::put_settings(&mut preface, &[]);
    let mut failed = session.feed(&preface).is_err();
    while !failed && !data.is_empty() {
        let len = usize::from(data[0]).min(data.len() - 1);
        let (read, rest) = data[1..].split_at(len);
        data = rest;
        match session.feed(read) {
            Ok(happened) => {
                for happened in happened {
                    match happened {
                        Happened::Request { slot, begin, head } => {
                            responder.request(slot, &begin, &head);
                            session.ready.mark(slot);
                        }
                        Happened::Cancel { slot } => responder.cancel(slot),
                    }
                }
                responder.run(&mut session, false);
            }
            Err(reason) => {
                responder.stop();
                session.engine.fail(reason);
                failed = true;
            }
        }
        assert!(session.engine.streams() <= MAX_STREAMS as usize);
        if !failed {
            session.engine.check_windows();
        }
        // One read asks for at most its own size in replies, and streams stop at the high
        // mark, each overshooting it by less than one chunk of their body.
        assert!(
            session.engine.out.len() <= 2 * OUT_HIGH + 256 * 32 + 64 * 1024,
            "{} bytes queued",
            session.engine.out.len()
        );
        // What is written is let go of: the queue holds what is unwritten, and less than
        // one high mark of what is not.
        assert!(
            session.engine.out.held() <= session.engine.out.len() + 2 * OUT_HIGH,
            "{} bytes held for {} queued",
            session.engine.out.held(),
            session.engine.out.len()
        );
        if reads_output || failed {
            let takes = if failed { usize::MAX } else { takes };
            check(&mut session, &mut responder, takes);
            responder.run(&mut session, false);
        }
    }
    check(&mut session, &mut responder, usize::MAX);
    assert!(wire.is_empty(), "the last frame is whole");
    assert!(responder.sent.is_empty(), "every head sent was written");
}

/// Fuzz entry: a field block. Whatever decodes is encoded again as a response would be,
/// and a second decoder must read the same fields back.
pub fn hpack_input(data: &[u8]) {
    thread_local! {
        static STATE: std::cell::RefCell<(Decoder, Encoder, Decoder)> =
            std::cell::RefCell::new((Decoder::new(), Encoder::new(), Decoder::new()));
    }
    STATE.with_borrow_mut(|state| {
        let (decoder, encoder, peer) = &mut *state;
        let mut fields: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut size = 0;
        let decoded = decoder.decode(data, |name, value| {
            size += name.len() + value.len();
            fields.push((name.to_vec(), value.to_vec()));
        });
        // A string is at most 8/5 of its coded bytes, a table entry at most the table.
        assert!(size <= data.len() * 8 / 5 + data.len() * super::hpack::TABLE_SIZE);
        if decoded.is_err() {
            // The table is out of step with whatever sent the block: start over.
            *state = (Decoder::new(), Encoder::new(), Decoder::new());
            return;
        }
        let sendable = |value: &[u8]| !value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f);
        let mut block = Vec::new();
        encoder.begin(&mut block);
        for (name, value) in &fields {
            encoder.field(&mut block, name, value);
        }
        let mut back = Vec::new();
        peer.decode(&block, |name, value| {
            back.push((name.to_vec(), value.to_vec()))
        })
        .expect("an encoded block decodes");
        // The encoder cuts the whitespace around a value and leaves out what no field
        // may hold.
        for (_, value) in &mut fields {
            *value = value.trim_ascii().to_vec();
        }
        fields.retain(|(_, value)| sendable(value));
        assert_eq!(back, fields);
    });
}
