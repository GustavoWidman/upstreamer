//! A minimal HTTP/1.1 client for the Kubernetes API: one `GET` per connection, `Connection:
//! close`, TLS through rustls' buffered API on a tokio socket, and a response body that is
//! read incrementally (a watch is one chunked response that lasts minutes).

use super::config::Cluster;
use memchr::memchr;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

/// Longest response head, and longest single JSON line of a watch.
const MAX_HEAD: usize = 64 * 1024;
const MAX_LINE: usize = 16 * 1024 * 1024;
/// A list answer or an error body larger than this is a misbehaving server.
pub(super) const MAX_BODY: usize = 64 * 1024 * 1024;

/// Why a request failed.
#[derive(Debug)]
pub(super) enum Failure {
    /// The server said `410 Gone` (or an `ERROR` event with that code): the resource version
    /// is too old, so the caller relists.
    Gone,
    Other(String),
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure::Other(message)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::Gone => f.write_str("resource version too old (410 Gone)"),
            Failure::Other(message) => f.write_str(message),
        }
    }
}

trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// A response whose head was read and whose status is `200`.
pub(super) struct Response {
    body: Body,
}

/// `GET path` on the cluster. `head_timeout` bounds connecting, the TLS handshake and the
/// response head. A non-`200` answer is a [`Failure`] carrying the server's own message.
pub(super) async fn get(
    cluster: &mut Cluster,
    path: &str,
    head_timeout: Duration,
) -> Result<Response, Failure> {
    let target = format!("{}{path}", cluster.endpoint.prefix);
    let token = cluster.token()?.map(str::to_owned);
    let what = format!(
        "{}:{}{target}",
        cluster.endpoint.host, cluster.endpoint.port
    );
    let attempt = async {
        let io = connect(cluster).await?;
        request(io, cluster, &target, token.as_deref()).await
    };
    let (status, body) = match tokio::time::timeout(head_timeout, attempt).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(e)) => return Err(Failure::Other(format!("GET {what}: {e}"))),
        Err(_) => return Err(Failure::Other(format!("GET {what}: timed out"))),
    };
    answer(status, body, &what).await
}

/// What an answer with a parsed head means: a `200` body to read, or a failure.
async fn answer(status: u16, body: Body, what: &str) -> Result<Response, Failure> {
    if status == 200 {
        return Ok(Response { body });
    }
    if status == 410 {
        return Err(Failure::Gone);
    }
    let mut body = body;
    let text = body
        .read_to_end(64 * 1024)
        .await
        .map(|bytes| status_message(&bytes))
        .unwrap_or_default();
    Err(Failure::Other(
        format!("GET {what}: HTTP {status} {text}")
            .trim_end()
            .to_owned(),
    ))
}

impl Response {
    /// The whole body, bounded by [`MAX_BODY`].
    pub async fn read_to_end(mut self) -> io::Result<Vec<u8>> {
        self.body.read_to_end(MAX_BODY).await
    }

    /// The next line of the body without its newline; `None` at a clean end. Cancel safe: an
    /// interrupted call loses nothing.
    pub async fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.body.next_line().await
    }
}

/// A response read from `io`, as [`get`] reads one from the API server.
#[cfg(feature = "internals")]
pub(super) async fn read_response(
    io: impl AsyncRead + AsyncWrite + Send + Unpin + 'static,
) -> Result<Response, Failure> {
    let (status, body) = read_head(Box::new(io))
        .await
        .map_err(|e| Failure::Other(e.to_string()))?;
    answer(status, body, "fuzz").await
}

/// The `message` of a `Status` object, else the first line of whatever came back.
fn status_message(body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body)
        && let Some(message) = value.get("message").and_then(|m| m.as_str())
    {
        return message.to_owned();
    }
    String::from_utf8_lossy(body)
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect()
}

async fn connect(cluster: &Cluster) -> io::Result<Box<dyn Io>> {
    let endpoint = &cluster.endpoint;
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port)).await?;
    tcp.set_nodelay(true)?;
    // A watch is silent for minutes; keepalive notices a vanished API server (a failed
    // control-plane node, a dropped NAT entry) long before the watch's own deadline.
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    socket2::SockRef::from(&tcp).set_tcp_keepalive(&keepalive)?;
    match &cluster.tls {
        None => Ok(Box::new(tcp)),
        Some(tls) => {
            let conn = rustls::ClientConnection::new(tls.config.clone(), tls.name.clone())
                .map_err(io::Error::other)?;
            Ok(Box::new(TlsStream { tcp, conn }))
        }
    }
}

async fn request(
    mut io: Box<dyn Io>,
    cluster: &Cluster,
    target: &str,
    token: Option<&str>,
) -> io::Result<(u16, Body)> {
    let endpoint = &cluster.endpoint;
    let mut head = String::with_capacity(256);
    head.push_str("GET ");
    head.push_str(target);
    head.push_str(" HTTP/1.1\r\nHost: ");
    if endpoint.host.contains(':') {
        head.push_str(&format!("[{}]", endpoint.host));
    } else {
        head.push_str(&endpoint.host);
    }
    head.push_str(&format!(":{}", endpoint.port));
    head.push_str(
        "\r\nUser-Agent: upstreamer\r\nAccept: application/json\r\nConnection: close\r\n",
    );
    if let Some(token) = token {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    io.write_all(head.as_bytes()).await?;
    io.flush().await?;
    read_head(io).await
}

/// Reads a response head; the body is left to read from `io`.
async fn read_head(mut io: Box<dyn Io>) -> io::Result<(u16, Body)> {
    let mut raw = Vec::with_capacity(8 * 1024);
    loop {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&raw) {
            Ok(httparse::Status::Complete(used)) => {
                let status = response.code.unwrap_or(0);
                let framing = framing(response.headers)?;
                raw.drain(..used);
                let body = Body {
                    io,
                    raw,
                    framing,
                    out: Vec::new(),
                    scanned: 0,
                };
                return Ok((status, body));
            }
            Ok(httparse::Status::Partial) if raw.len() < MAX_HEAD => {}
            Ok(httparse::Status::Partial) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response head too long",
                ));
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
        if io.read_buf(&mut raw).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

fn framing(headers: &[httparse::Header<'_>]) -> io::Result<Framing> {
    let mut length = None;
    for header in headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            let value = std::str::from_utf8(header.value).unwrap_or("");
            if value
                .rsplit(',')
                .next()
                .is_some_and(|last| last.trim().eq_ignore_ascii_case("chunked"))
            {
                return Ok(Framing::Chunked(Chunk::Size));
            }
        } else if header.name.eq_ignore_ascii_case("content-length") {
            length = std::str::from_utf8(header.value)
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok());
            if length.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bad Content-Length",
                ));
            }
        }
    }
    Ok(match length {
        Some(n) => Framing::Length(n),
        None => Framing::Close,
    })
}

enum Framing {
    Length(u64),
    Chunked(Chunk),
    /// No length: the body ends when the server closes.
    Close,
}

#[derive(Clone, Copy)]
enum Chunk {
    Size,
    Data(u64),
    /// The CRLF after a chunk's data.
    DataEnd,
    /// After the last chunk: trailer lines up to the empty one.
    Trailer,
    Done,
}

/// The response body. Bytes read from the socket wait in `raw` until the framing decodes
/// them into `out`; decoding never awaits, so the one await point (the socket read) can be
/// cancelled without losing state.
struct Body {
    io: Box<dyn Io>,
    raw: Vec<u8>,
    framing: Framing,
    /// Decoded, not yet consumed.
    out: Vec<u8>,
    /// The part of `out` known to hold no newline.
    scanned: usize,
}

impl Body {
    /// Decodes buffered bytes into `out`. `Ok(false)` once the body is complete.
    fn decode(&mut self) -> io::Result<bool> {
        let bad = |what| io::Error::new(io::ErrorKind::InvalidData, what);
        loop {
            match &mut self.framing {
                Framing::Close => {
                    self.out.append(&mut self.raw);
                    return Ok(true);
                }
                Framing::Length(0) => return Ok(false),
                Framing::Length(left) => {
                    let take = self
                        .raw
                        .len()
                        .min(usize::try_from(*left).unwrap_or(usize::MAX));
                    self.out.extend_from_slice(&self.raw[..take]);
                    self.raw.drain(..take);
                    *left -= take as u64;
                    return Ok(true);
                }
                Framing::Chunked(state) => match *state {
                    Chunk::Done => return Ok(false),
                    Chunk::Size => {
                        let Some(end) = memchr(b'\n', &self.raw) else {
                            if self.raw.len() > 1024 {
                                return Err(bad("chunk size line too long"));
                            }
                            return Ok(true);
                        };
                        let line = std::str::from_utf8(&self.raw[..end])
                            .map_err(|_| bad("bad chunk size"))?;
                        let digits = line.split(';').next().unwrap_or("").trim();
                        let size =
                            u64::from_str_radix(digits, 16).map_err(|_| bad("bad chunk size"))?;
                        self.raw.drain(..=end);
                        *state = if size == 0 {
                            Chunk::Trailer
                        } else {
                            Chunk::Data(size)
                        };
                    }
                    Chunk::Data(left) => {
                        if self.raw.is_empty() {
                            return Ok(true);
                        }
                        let take = self
                            .raw
                            .len()
                            .min(usize::try_from(left).unwrap_or(usize::MAX));
                        self.out.extend_from_slice(&self.raw[..take]);
                        self.raw.drain(..take);
                        *state = if left == take as u64 {
                            Chunk::DataEnd
                        } else {
                            Chunk::Data(left - take as u64)
                        };
                        return Ok(true);
                    }
                    Chunk::DataEnd => {
                        if self.raw.len() < 2 {
                            return Ok(true);
                        }
                        if &self.raw[..2] != b"\r\n" {
                            return Err(bad("chunk not followed by CRLF"));
                        }
                        self.raw.drain(..2);
                        *state = Chunk::Size;
                    }
                    Chunk::Trailer => {
                        let Some(end) = memchr(b'\n', &self.raw) else {
                            return Ok(true);
                        };
                        let empty = end == 0 || (end == 1 && self.raw[0] == b'\r');
                        self.raw.drain(..=end);
                        if empty {
                            *state = Chunk::Done;
                        }
                    }
                },
            }
        }
    }

    /// More decoded bytes in `out`; `false` at the end of the body.
    async fn fill(&mut self) -> io::Result<bool> {
        loop {
            let before = self.out.len();
            let more = self.decode()?;
            if self.out.len() > before {
                return Ok(true);
            }
            if !more {
                return Ok(false);
            }
            if self.io.read_buf(&mut self.raw).await? == 0 {
                return match self.framing {
                    Framing::Close => Ok(false),
                    _ => Err(io::ErrorKind::UnexpectedEof.into()),
                };
            }
        }
    }

    async fn next_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(at) = memchr(b'\n', &self.out[self.scanned..]) {
                let end = self.scanned + at;
                let mut line: Vec<u8> = self.out.drain(..=end).collect();
                self.scanned = 0;
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(Some(line));
            }
            self.scanned = self.out.len();
            if self.out.len() > MAX_LINE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "watch event too large",
                ));
            }
            if !self.fill().await? {
                self.scanned = 0;
                return Ok((!self.out.is_empty()).then(|| std::mem::take(&mut self.out)));
            }
        }
    }

    async fn read_to_end(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        while self.fill().await? {
            if self.out.len() > limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "response too large",
                ));
            }
        }
        Ok(std::mem::take(&mut self.out))
    }
}

/// A rustls client connection over a tokio socket: rustls owns the record buffers, this moves
/// ciphertext between them and the socket.
struct TlsStream {
    tcp: TcpStream,
    conn: rustls::ClientConnection,
}

/// The socket as the blocking reader and writer rustls expects, inside one poll: a wait
/// becomes `WouldBlock`, with the task's waker registered.
struct Blocking<'a, 'b> {
    tcp: &'a mut TcpStream,
    cx: &'a mut Context<'b>,
}

impl Read for Blocking<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut dst = ReadBuf::new(buf);
        match Pin::new(&mut *self.tcp).poll_read(self.cx, &mut dst) {
            Poll::Ready(Ok(())) => Ok(dst.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl Write for Blocking<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.tcp).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TlsStream {
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.conn.wants_write() {
            let mut socket = Blocking {
                tcp: &mut self.tcp,
                cx,
            };
            match self.conn.write_tls(&mut socket) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Reads ciphertext and decrypts it; `Ok(0)` when the server closed the socket.
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut socket = Blocking {
            tcp: &mut self.tcp,
            cx,
        };
        let n = match self.conn.read_tls(&mut socket) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Err(e) = self.conn.process_new_packets() {
            let _ = self.poll_send(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
        }
        Poll::Ready(Ok(n))
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.conn.reader().read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                // The server closed without close_notify. Body framing tells a complete
                // response from a truncated one, so this is an end of stream.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(e)),
            }
            ready!(this.poll_send(cx))?;
            if ready!(this.poll_receive(cx))? == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let n = this.conn.writer().write(buf)?;
        // The record is queued in rustls; a socket that is full only delays the next poll.
        match this.poll_send(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            _ => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.writer().flush()?;
        this.poll_send(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.conn.send_close_notify();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.tcp).poll_shutdown(cx)
    }
}
