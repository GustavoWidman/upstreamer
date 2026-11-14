//! HTTP/1.1 origin for the proxy benchmarks.
//!
//! `GET /bytes/<n>` answers with an n-byte body, any other path with a 2-byte
//! body. Request bodies (Content-Length or chunked) are read and discarded.
//! `GET /__stats` reports counters as JSON and is not counted itself.
//!
//! One thread per core, each with its own SO_REUSEPORT listener and a
//! single-threaded runtime, so no lock or cross-thread wakeup sits on the
//! request path.

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_BODY: usize = 64 << 20;
const READ_CHUNK: usize = 64 << 10;
const MAX_HEAD: usize = 64 << 10;

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static BODY_BYTES_IN: AtomicU64 = AtomicU64::new(0);
static BODY_BYTES_OUT: AtomicU64 = AtomicU64::new(0);
static NON_GET_REQUESTS: AtomicU64 = AtomicU64::new(0);

fn payload() -> &'static [u8] {
    static PAYLOAD: OnceLock<Vec<u8>> = OnceLock::new();
    PAYLOAD.get_or_init(|| vec![b'x'; MAX_BODY])
}

struct Args {
    listen: SocketAddr,
    threads: usize,
}

fn parse_args() -> Args {
    let mut listen: SocketAddr = "127.0.0.1:18080".parse().unwrap();
    let mut threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => listen = value.parse().expect("--listen <addr:port>"),
            "--threads" => threads = value.parse().expect("--threads <n>"),
            _ => panic!("unknown flag {flag}"),
        }
    }
    Args { listen, threads }
}

fn listener(addr: SocketAddr) -> std::net::TcpListener {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.set_reuse_port(true).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket.bind(&addr.into()).unwrap();
    socket.listen(4096).unwrap();
    socket.into()
}

fn main() {
    let args = parse_args();
    payload();
    let workers: Vec<_> = (0..args.threads)
        .map(|_| {
            let std_listener = listener(args.listen);
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .build()
                    .unwrap();
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let listener = TcpListener::from_std(std_listener).unwrap();
                    loop {
                        let Ok((stream, _)) = listener.accept().await else { continue };
                        CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                        tokio::task::spawn_local(async move {
                            let _ = serve(stream).await;
                        });
                    }
                });
            })
        })
        .collect();
    eprintln!("bench-origin listening on {} with {} threads", args.listen, args.threads);
    for worker in workers {
        worker.join().unwrap();
    }
}

enum Framing {
    None,
    Length(usize),
    Chunked,
}

struct Head {
    len: usize,
    framing: Framing,
    close: bool,
    expect_continue: bool,
    response_bytes: Option<usize>,
    counted: bool,
}

fn header_is(value: &[u8], token: &str) -> bool {
    value
        .split(|&b| b == b',')
        .any(|part| part.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
}

fn parse_head(buf: &[u8]) -> Result<Option<Head>, ()> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let len = match req.parse(buf) {
        Ok(httparse::Status::Complete(len)) => len,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(_) => return Err(()),
    };
    let mut framing = Framing::None;
    let mut close = req.version == Some(0);
    let mut expect_continue = false;
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            let n = std::str::from_utf8(h.value).map_err(|_| ())?.trim().parse().map_err(|_| ())?;
            framing = Framing::Length(n);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") && header_is(h.value, "chunked") {
            framing = Framing::Chunked;
        } else if h.name.eq_ignore_ascii_case("connection") {
            if header_is(h.value, "close") {
                close = true;
            } else if header_is(h.value, "keep-alive") {
                close = false;
            }
        } else if h.name.eq_ignore_ascii_case("expect") && header_is(h.value, "100-continue") {
            expect_continue = true;
        }
    }
    let path = req.path.unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);
    let counted = path != "/__stats";
    if counted && req.method != Some("GET") {
        NON_GET_REQUESTS.fetch_add(1, Ordering::Relaxed);
    }
    let response_bytes = if counted {
        Some(
            path.strip_prefix("/bytes/")
                .and_then(|n| n.parse::<usize>().ok())
                .map_or(2, |n| n.min(MAX_BODY)),
        )
    } else {
        None
    };
    Ok(Some(Head { len, framing, close, expect_continue, response_bytes, counted }))
}

struct Conn {
    stream: TcpStream,
    buf: Vec<u8>,
    start: usize,
}

impl Conn {
    fn pending(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    async fn fill(&mut self) -> std::io::Result<bool> {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > 0 && self.buf.len() + READ_CHUNK > self.buf.capacity() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let old = self.buf.len();
        self.buf.resize(old + READ_CHUNK, 0);
        let n = self.stream.read(&mut self.buf[old..]).await?;
        self.buf.truncate(old + n);
        Ok(n > 0)
    }

    async fn skip(&mut self, mut n: usize) -> std::io::Result<()> {
        while n > 0 {
            if self.pending().is_empty() && !self.fill().await? {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            let take = n.min(self.pending().len());
            self.start += take;
            n -= take;
        }
        Ok(())
    }

    async fn line(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            if let Some(i) = self.pending().windows(2).position(|w| w == b"\r\n") {
                let line = self.pending()[..i].to_vec();
                self.start += i + 2;
                return Ok(line);
            }
            if self.pending().len() > MAX_HEAD || !self.fill().await? {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        }
    }

    async fn skip_chunked(&mut self) -> std::io::Result<usize> {
        let mut total = 0;
        loop {
            let line = self.line().await?;
            let size = line.split(|&b| b == b';').next().unwrap_or(&[]);
            let size = std::str::from_utf8(size)
                .ok()
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
                .ok_or(std::io::ErrorKind::InvalidData)?;
            if size == 0 {
                while !self.line().await?.is_empty() {}
                return Ok(total);
            }
            self.skip(size).await?;
            if !self.line().await?.is_empty() {
                return Err(std::io::ErrorKind::InvalidData.into());
            }
            total += size;
        }
    }
}

fn stats_json() -> String {
    format!(
        "{{\"requests\":{},\"connections\":{},\"body_bytes_in\":{},\"body_bytes_out\":{},\"non_get_requests\":{}}}",
        REQUESTS.load(Ordering::Relaxed),
        CONNECTIONS.load(Ordering::Relaxed),
        BODY_BYTES_IN.load(Ordering::Relaxed),
        BODY_BYTES_OUT.load(Ordering::Relaxed),
        NON_GET_REQUESTS.load(Ordering::Relaxed),
    )
}

async fn serve(stream: TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let mut conn = Conn { stream, buf: Vec::with_capacity(2 * READ_CHUNK), start: 0 };
    let mut out = Vec::with_capacity(READ_CHUNK);
    loop {
        let head = loop {
            match parse_head(conn.pending()) {
                Ok(Some(head)) => break head,
                Ok(None) if conn.pending().len() < MAX_HEAD => {
                    if !conn.fill().await? {
                        return Ok(());
                    }
                }
                _ => {
                    conn.stream
                        .write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .await?;
                    return Ok(());
                }
            }
        };
        conn.start += head.len;
        if head.expect_continue {
            conn.stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        }
        let body_in = match head.framing {
            Framing::None => 0,
            Framing::Length(n) => {
                conn.skip(n).await?;
                n
            }
            Framing::Chunked => conn.skip_chunked().await?,
        };

        let stats;
        let (status_line, body): (&str, &[u8]) = match head.response_bytes {
            Some(n) => ("HTTP/1.1 200 OK", &payload()[..n]),
            None => {
                stats = stats_json();
                ("HTTP/1.1 200 OK", stats.as_bytes())
            }
        };
        if head.counted {
            REQUESTS.fetch_add(1, Ordering::Relaxed);
            BODY_BYTES_IN.fetch_add(body_in as u64, Ordering::Relaxed);
            BODY_BYTES_OUT.fetch_add(body.len() as u64, Ordering::Relaxed);
        }

        out.clear();
        out.extend_from_slice(status_line.as_bytes());
        out.extend_from_slice(b"\r\ncontent-type: application/octet-stream\r\ncontent-length: ");
        out.extend_from_slice(body.len().to_string().as_bytes());
        if head.close {
            out.extend_from_slice(b"\r\nconnection: close");
        }
        out.extend_from_slice(b"\r\n\r\n");
        if body.len() <= READ_CHUNK {
            out.extend_from_slice(body);
            conn.stream.write_all(&out).await?;
        } else {
            conn.stream.write_all(&out).await?;
            conn.stream.write_all(body).await?;
        }
        if head.close {
            conn.stream.shutdown().await?;
            return Ok(());
        }
    }
}
