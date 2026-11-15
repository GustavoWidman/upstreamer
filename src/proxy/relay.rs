//! Moving bodies between two streams without buffering them whole.
//!
//! h1 <-> h1 bodies are relayed as raw framed bytes: a Content-Length body is copied as is, a
//! chunked body is forwarded chunk syntax and all while a [`Tracker`] follows where it ends.
//! Every read is written before the next read, so SSE events and DERP frames go out as they
//! arrive; there is no flush interval because there is no buffering.
//!
//! A body that turns out long moves to a 64 KiB buffer, so a megabyte takes about sixteen
//! reads and writes. When both streams expose a kernel-plaintext descriptor the copy loops
//! can become splice(2) through a per-core pipe without changing these signatures.

use super::UpstreamBody;
use super::conn::{UpstreamConn, UpstreamIo, poll_read_buf};
use crate::net::Transport;
use crate::net::buf::{LARGE, SMALL};
use crate::proto::h1::codec::{Chunked, Framing, ParseError, Scan};
use crate::proto::h1::server::H1Body;
use crate::runtime::Core;
use bytes::{Buf, Bytes, BytesMut};
use smallvec::SmallVec;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Where a message body ends in the raw bytes that carry it.
#[derive(Debug)]
pub(crate) struct Tracker {
    framing: Framing,
    chunked: Chunked,
    /// `Length` framing: body bytes not yet seen.
    left: u64,
    ended: bool,
}

impl Tracker {
    pub fn new(framing: Framing) -> Tracker {
        Tracker {
            framing,
            chunked: Chunked::default(),
            left: match framing {
                Framing::Length(n) => n,
                _ => 0,
            },
            ended: matches!(framing, Framing::None | Framing::Length(0)),
        }
    }

    pub fn framing(&self) -> Framing {
        self.framing
    }

    /// Whether every byte of the body has been seen.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// Body bytes still to come, when the framing says so. Before any byte was seen, that is
    /// the body's length.
    pub fn remaining(&self) -> Option<u64> {
        match self.framing {
            Framing::None => Some(0),
            Framing::Length(_) => Some(self.left),
            Framing::Chunked | Framing::UntilClose => None,
        }
    }

    /// Takes `input`, the raw bytes that follow those already seen, and returns how many of
    /// them belong to the body. Fewer than all of them means the body ended there.
    pub fn scan(&mut self, input: &[u8]) -> Result<usize, ParseError> {
        if self.ended {
            return Ok(0);
        }
        match self.framing {
            Framing::None => Ok(0),
            Framing::Length(_) => {
                let n = self.left.min(input.len() as u64);
                self.left -= n;
                self.ended = self.left == 0;
                Ok(n as usize)
            }
            Framing::Chunked => match self.chunked.scan(input)? {
                Scan::More => Ok(input.len()),
                Scan::End(n) => {
                    self.ended = true;
                    Ok(n)
                }
            },
            Framing::UntilClose => Ok(input.len()),
        }
    }

    /// [`Tracker::scan`] for a reader that wants the data without chunk syntax: the ranges of
    /// `input` that are body data are appended to `data`.
    pub fn decode(
        &mut self,
        input: &[u8],
        data: &mut SmallVec<[Range<usize>; 4]>,
    ) -> Result<usize, ParseError> {
        if self.framing == Framing::Chunked && !self.ended {
            let (taken, ended) = self.chunked.decode(input, data)?;
            self.ended = ended;
            return Ok(taken);
        }
        let taken = self.scan(input)?;
        if taken > 0 {
            data.push(0..taken);
        }
        Ok(taken)
    }

    /// The source closed. Returns whether the body is complete: a close-delimited body ends
    /// here, any other framing must have ended before.
    pub fn close(&mut self) -> bool {
        if self.framing == Framing::UntilClose {
            self.ended = true;
        }
        self.ended
    }
}

/// How far a request body got on its way to the origin.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sent {
    All,
    /// The origin answered, or stopped taking bytes, before the body ended. Whatever it sent
    /// is in the connection's buffer; the rest of the body was not forwarded.
    Interrupted,
}

/// Request body, client -> origin. `head`, already serialised, goes out in one writev with
/// the body bytes that arrived with the request. The error is the client's: its connection
/// failed, closed mid-body, or sent broken chunk framing.
pub(crate) async fn copy_request(
    core: &Core,
    head: &[u8],
    body: &mut H1Body<'_>,
    up: &mut UpstreamConn,
) -> io::Result<Sent> {
    let first = body.buffered()?;
    let n = first.len();
    let wrote = up
        .io
        .write_all_vectored(&mut [IoSlice::new(head), IoSlice::new(first)])
        .await;
    if wrote.is_err() {
        return Ok(Sent::Interrupted);
    }
    body.consume(n);
    loop {
        body.prefer_large(core);
        let chunk = tokio::select! {
            biased;
            chunk = body.raw() => chunk?,
            _ = up.io.read(&mut up.buf) => return Ok(Sent::Interrupted),
        };
        let Some(chunk) = chunk else {
            return Ok(Sent::All);
        };
        let n = chunk.len();
        if !matches!(
            write_unless_answered(&mut up.io, &mut up.buf, chunk).await,
            Ok(true)
        ) {
            return Ok(Sent::Interrupted);
        }
        body.consume(n);
    }
}

/// Writes `data` to the origin. `Ok(false)` when the origin sent bytes (now in `answer`) or
/// closed while it was not taking ours: a response that arrives early must be read, or both
/// sides wait on full socket buffers forever.
async fn write_unless_answered(
    io: &mut UpstreamIo,
    answer: &mut BytesMut,
    data: &[u8],
) -> io::Result<bool> {
    let mut rest = data;
    poll_fn(|cx| {
        while !rest.is_empty() {
            match Pin::new(&mut *io).poll_write(cx, rest) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => rest = &rest[n..],
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return poll_read_buf(&mut *io, cx, answer).map(|read| read.map(|_| false));
                }
            }
        }
        Pin::new(&mut *io).poll_flush(cx).map_ok(|()| true)
    })
    .await
}

/// How an origin's body bytes are written to an h1 client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rewrite {
    /// As they came: a body with a length, a chunked body with its chunk syntax, or a
    /// close-delimited body for a client that reads to the close.
    Raw,
    /// Chunk syntax removed, for an HTTP/1.0 client.
    Unchunk,
    /// Chunk syntax added to a close-delimited body, so the client's connection outlives it.
    Chunk,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelayEnd {
    /// The message ended cleanly; both sides may be reused.
    Complete,
    /// The source closed early or a side failed; neither side is reusable.
    Broken,
}

/// Response body, origin -> h1 client. `head` goes out in one writev with the body bytes that
/// arrived with the origin's head. While it waits for more of the body it watches the client:
/// when the client closes, the relay ends, so the origin's connection closes too. Bytes the
/// client sends meanwhile stay in `client_buf`. `sent` counts the bytes written after the head.
pub(crate) async fn copy_response(
    core: &Core,
    mut head: &[u8],
    body: &mut UpstreamBody,
    rewrite: Rewrite,
    client: &mut Transport,
    client_buf: &mut BytesMut,
    sent: &mut u64,
) -> RelayEnd {
    let UpstreamBody { conn, track, .. } = body;
    let mut data: SmallVec<[Range<usize>; 4]> = SmallVec::new();
    loop {
        let full = conn.buf.len() == conn.buf.capacity();
        data.clear();
        let taken = match rewrite {
            Rewrite::Unchunk => track.decode(&conn.buf, &mut data),
            Rewrite::Raw | Rewrite::Chunk => track.scan(&conn.buf),
        };
        let Ok(taken) = taken else {
            return RelayEnd::Broken;
        };
        let part = Part {
            head,
            bytes: &conn.buf[..taken],
            data: &data,
            last: track.ended(),
        };
        match part.write(rewrite, client).await {
            Ok(n) => *sent += n,
            Err(_) => return RelayEnd::Broken,
        }
        head = &[];
        conn.buf.advance(taken);
        if track.ended() {
            return RelayEnd::Complete;
        }
        let long = track.remaining().map_or(full, |n| n > SMALL as u64);
        if long && conn.buf.is_empty() && conn.buf.capacity() < LARGE {
            core.bufs
                .put(std::mem::replace(&mut conn.buf, core.bufs.take_large()));
        }
        let read = tokio::select! {
            biased;
            read = conn.io.read(&mut conn.buf) => read,
            () = closed(client, client_buf) => return RelayEnd::Broken,
        };
        match read {
            Ok(0) if track.close() => {}
            Ok(0) | Err(_) => return RelayEnd::Broken,
            Ok(_) => {}
        }
    }
}

/// One write of a response relay.
struct Part<'a> {
    /// The response head, on the first write.
    head: &'a [u8],
    /// Raw body bytes, as the origin framed them.
    bytes: &'a [u8],
    /// Ranges of `bytes` that are data, when chunk syntax is being removed.
    data: &'a [Range<usize>],
    /// The body ends with these bytes.
    last: bool,
}

impl Part<'_> {
    /// Returns the bytes written after the head.
    async fn write(&self, rewrite: Rewrite, client: &mut Transport) -> io::Result<u64> {
        let mut size = [0u8; 18];
        let mut slices: SmallVec<[IoSlice<'_>; 6]> = SmallVec::new();
        match rewrite {
            Rewrite::Raw => {
                slices.push(IoSlice::new(self.head));
                slices.push(IoSlice::new(self.bytes));
            }
            Rewrite::Unchunk => {
                slices.push(IoSlice::new(self.head));
                for range in self.data {
                    slices.push(IoSlice::new(&self.bytes[range.clone()]));
                }
            }
            Rewrite::Chunk => {
                slices.extend(framed(self.head, self.bytes, true, self.last, &mut size));
            }
        }
        let len: usize = slices.iter().map(|s| s.len()).sum();
        if len == 0 {
            return Ok(0);
        }
        client.write_all_vectored(&mut slices).await?;
        Ok((len - self.head.len()) as u64)
    }
}

/// The slices of one write of a body produced in pieces: `head` (empty after the first
/// write), then `data` as it is or as one chunk, then the last chunk when the body is
/// `chunked` and this write ends it.
pub(crate) fn framed<'a>(
    head: &'a [u8],
    data: &'a [u8],
    chunked: bool,
    last: bool,
    size: &'a mut [u8; 18],
) -> SmallVec<[IoSlice<'a>; 5]> {
    let mut slices = SmallVec::new();
    slices.push(IoSlice::new(head));
    if chunked && !data.is_empty() {
        slices.push(IoSlice::new(chunk_size(data.len(), size)));
        slices.push(IoSlice::new(data));
        slices.push(IoSlice::new(b"\r\n"));
    } else {
        slices.push(IoSlice::new(data));
    }
    if chunked && last {
        slices.push(IoSlice::new(LAST_CHUNK));
    }
    slices
}

/// Cuts the body bytes at the front of `buf` off it and returns their data, without chunk
/// syntax. `None` when `buf` holds no data of the body: read more, unless the body ended.
pub(crate) fn take_data(
    track: &mut Tracker,
    buf: &mut BytesMut,
) -> Result<Option<Bytes>, ParseError> {
    let mut data: SmallVec<[Range<usize>; 4]> = SmallVec::new();
    let taken = track.decode(buf, &mut data)?;
    let mut raw = buf.split_to(taken);
    Ok(match data.as_slice() {
        [] => None,
        [one] => {
            raw.truncate(one.end);
            raw.advance(one.start);
            Some(raw.freeze())
        }
        ranges => {
            let mut joined = BytesMut::with_capacity(ranges.iter().map(Range::len).sum());
            for range in ranges {
                joined.extend_from_slice(&raw[range.clone()]);
            }
            Some(joined.freeze())
        }
    })
}

/// The end of a chunked body without trailers.
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// The size line of a chunk of `len` bytes: hex digits and CRLF.
fn chunk_size(len: usize, line: &mut [u8; 18]) -> &[u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut start = 16;
    let mut n = len;
    loop {
        start -= 1;
        line[start] = HEX[n & 15];
        n >>= 4;
        if n == 0 {
            break;
        }
    }
    line[16] = b'\r';
    line[17] = b'\n';
    &line[start..]
}

/// Resolves when the client closes its side or its connection fails. What it sends meanwhile
/// (a pipelined request) is kept in `buf`, up to 64 KiB; past that the client is no longer
/// watched.
pub(crate) async fn closed(client: &mut Transport, buf: &mut BytesMut) {
    while buf.len() < LARGE {
        if !matches!(client.read(buf).await, Ok(n) if n > 0) {
            return;
        }
    }
    std::future::pending().await
}

/// After a 101: bytes both ways until either side closes and what it sent is delivered, or
/// nothing moved for `idle`. Bytes already read from either side go first. `to_client` counts
/// the bytes delivered to the client.
pub(crate) async fn tunnel(
    client: &mut Transport,
    client_buf: &mut BytesMut,
    up: &mut UpstreamConn,
    idle: Option<Duration>,
    to_client: &mut u64,
) -> io::Result<()> {
    let UpstreamConn { io, buf, watch, .. } = up;
    let (mut client_done, mut origin_done) = (false, false);
    let mut to_origin = 0;
    watch.set(idle);
    poll_fn(|cx| {
        loop {
            let mut moved = false;
            let up = pump(
                cx,
                client,
                io,
                client_buf,
                &mut client_done,
                &mut moved,
                &mut to_origin,
            )?;
            let down = pump(cx, io, client, buf, &mut origin_done, &mut moved, to_client)?;
            if moved {
                watch.set(idle);
            }
            match (up, down) {
                (Poll::Ready(()), Poll::Ready(())) => return Poll::Ready(Ok(())),
                // One direction is over: the other delivers what it holds, then ends too.
                (Poll::Ready(()), Poll::Pending) if !origin_done => origin_done = true,
                (Poll::Pending, Poll::Ready(())) if !client_done => client_done = true,
                _ => {
                    return watch
                        .poll_expired(cx)
                        .map(|()| Err(io::ErrorKind::TimedOut.into()));
                }
            }
        }
    })
    .await
}

/// Moves bytes one way through `buf`, adding what it writes to `count`. Ready once `done` (the
/// source ended, or the tunnel is closing) and everything read was written.
fn pump<R, W>(
    cx: &mut Context<'_>,
    from: &mut R,
    to: &mut W,
    buf: &mut BytesMut,
    done: &mut bool,
    moved: &mut bool,
    count: &mut u64,
) -> Poll<io::Result<()>>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        while !buf.is_empty() {
            let n = ready!(Pin::new(&mut *to).poll_write(cx, buf))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            buf.advance(n);
            *count += n as u64;
            *moved = true;
        }
        ready!(Pin::new(&mut *to).poll_flush(cx))?;
        if *done {
            return Poll::Ready(Ok(()));
        }
        if ready!(poll_read_buf(from, cx, buf))? == 0 {
            *done = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_all(framing: Framing, parts: &[&[u8]]) -> (Vec<usize>, bool) {
        let mut track = Tracker::new(framing);
        let taken = parts.iter().map(|p| track.scan(p).unwrap()).collect();
        (taken, track.ended())
    }

    #[test]
    fn a_body_without_framing_is_over_at_once() {
        assert!(Tracker::new(Framing::None).ended());
        assert!(Tracker::new(Framing::Length(0)).ended());
        assert_eq!(scan_all(Framing::None, &[b"GET /next"]), (vec![0], true));
    }

    #[test]
    fn a_length_ends_after_that_many_bytes_across_reads() {
        let mut track = Tracker::new(Framing::Length(10));
        assert_eq!(track.remaining(), Some(10));
        assert_eq!(track.scan(b"0123").unwrap(), 4);
        assert_eq!(track.remaining(), Some(6));
        assert!(!track.ended());
        assert_eq!(
            track.scan(b"456789GET /next").unwrap(),
            6,
            "bytes past the length belong to the next message"
        );
        assert!(track.ended());
        assert_eq!(track.scan(b"more").unwrap(), 0);
    }

    #[test]
    fn a_chunked_body_ends_after_its_last_chunk_and_trailers() {
        let parts: [&[u8]; 3] = [b"3\r\nab", b"c\r\n0\r\nx-t: 1\r\n", b"\r\nNEXT"];
        let (taken, ended) = scan_all(Framing::Chunked, &parts);
        assert_eq!(
            taken,
            [parts[0].len(), parts[1].len(), 2],
            "everything up to the empty line after the trailers"
        );
        assert!(ended);
        assert!(Tracker::new(Framing::Chunked).scan(b"zz\r\n").is_err());
    }

    #[test]
    fn a_close_delimited_body_ends_only_when_the_source_closes() {
        let mut track = Tracker::new(Framing::UntilClose);
        assert_eq!(track.scan(b"anything").unwrap(), 8);
        assert!(!track.ended());
        assert_eq!(track.remaining(), None);
        assert!(track.close(), "the close ends it cleanly");
        assert!(track.ended());
    }

    #[test]
    fn a_close_before_the_end_of_a_framed_body_is_a_truncation() {
        let mut track = Tracker::new(Framing::Length(5));
        track.scan(b"abc").unwrap();
        assert!(!track.close());
        let mut track = Tracker::new(Framing::Chunked);
        track.scan(b"5\r\nab").unwrap();
        assert!(!track.close());
    }

    #[test]
    fn decode_yields_data_without_chunk_syntax() {
        let mut track = Tracker::new(Framing::Chunked);
        let mut data = SmallVec::new();
        let input = b"2\r\nhi\r\n3;ext=1\r\nyou\r\n0\r\n\r\nNEXT";
        let taken = track.decode(input, &mut data).unwrap();
        assert_eq!(taken, input.len() - 4);
        assert!(track.ended());
        let joined: Vec<u8> = data
            .iter()
            .flat_map(|r| input[r.clone()].to_vec())
            .collect();
        assert_eq!(joined, b"hiyou");

        let mut track = Tracker::new(Framing::Length(3));
        let mut data = SmallVec::new();
        assert_eq!(track.decode(b"abcd", &mut data).unwrap(), 3);
        assert_eq!(data.into_vec(), vec![Range { start: 0, end: 3 }]);
    }

    #[test]
    fn chunk_size_lines_are_lowercase_hex() {
        let mut line = [0u8; 18];
        assert_eq!(chunk_size(1, &mut line), b"1\r\n");
        assert_eq!(chunk_size(255, &mut line), b"ff\r\n");
        assert_eq!(chunk_size(65536, &mut line), b"10000\r\n");
        assert_eq!(chunk_size(usize::MAX, &mut line), b"ffffffffffffffff\r\n");
    }
}
