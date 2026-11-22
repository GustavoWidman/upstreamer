//! The HTTP/1.1 and HTTP/2 connection drivers on an in-memory transport, for the fuzz targets.
//!
//! One core per thread serves one connection per input: the driver gets one end of a Unix
//! socket pair, the client's bytes go in at the other end in the pieces the input asks for,
//! and everything the driver writes is read back until it closes. The routes answer from
//! memory, from files, by redirect, by error route, with compression, or through an origin
//! in the same runtime that reads requests with this crate's own parser and answers in
//! every framing, with `100 Continue` and with upgrades.
//!
//! The runtime's clock is paused and moves only when nothing is ready, so every timeout
//! (header, keep-alive, idle origin) passes at once and the same input is served the same
//! way each time.

use super::*;
use crate::proto::h1::codec::{self, Chunked, Framing, Limits, Parsed, Scan};
use std::future::Future;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Longer than every timeout of the plan: a connection still open after it never ends.
const HANG: Duration = Duration::from_secs(3600);

struct Server {
    rt: tokio::runtime::Runtime,
    core: Rc<Core>,
    listener: ListenerKey,
    /// The core's unix clock and the runtime's clock when the server started: the core's
    /// clock moves with the runtime's, as the core's timer moves it with the system's.
    epoch: (i64, tokio::time::Instant),
}

thread_local! {
    static SERVER: Server = Server::new();
}

impl Server {
    fn new() -> Server {
        // As the proxy's own `main` does (Rust's runtime): a write to a closed peer is an
        // error, not a signal.
        // SAFETY: setting a signal's disposition to ignore has no preconditions.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        let origin = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                while let Ok((sock, _)) = listener.accept().await {
                    let _ = sock.set_nodelay(true);
                    tokio::spawn(origin(sock));
                }
            });
            addr
        });
        let files =
            std::env::temp_dir().join(format!("upstreamer-fuzz-conn-{}", std::process::id()));
        std::fs::create_dir_all(files.join("dir")).unwrap();
        std::fs::write(files.join("index.html"), "<p>index</p>\n").unwrap();
        std::fs::write(files.join("dir/a.txt"), "a\n".repeat(100)).unwrap();
        std::fs::write(files.join("big.bin"), vec![b'b'; 100 * 1024]).unwrap();
        let config = serde_json::json!({
            "version": 1,
            "listen": { "http": ["127.0.0.1:1"], "https": [] },
            "limits": { "maxStreams": 8, "maxHeadBytes": 8192, "maxHeaderFields": 32 },
            "sites": [{
                "name": "fuzz",
                "hosts": ["*"],
                "headers": { "X-Path": "{path}" },
                "routes": [
                    { "when": { "path": "/up/*" }, "proxy": {
                        "to": format!("http://{origin}"),
                        // A tunnel both ends leave idle stays open without it.
                        "timeouts": { "tunnelIdle": "10m" },
                    } },
                    { "when": { "path": "/files/*" }, "stripPrefix": "/files" },
                    { "when": { "path": ["/", "/dir/*", "/big.bin", "/index.html"] },
                      "files": { "root": files } },
                    { "when": { "path": "/enc/*" }, "encode": ["gzip", "zstd"] },
                    { "when": { "path": "/redir/*" }, "redirect": { "to": "/to{path}", "status": 302 } },
                    { "when": { "path": "/err/*" }, "error": 503 },
                    { "when": { "path": "/x/*" }, "error": 404 },
                    { "respond": { "body": "{method} {path} {header.User-Agent}\n" } },
                ],
                "errors": [{ "status": [503], "routes": [{ "respond": { "body": "{err.status_code}\n" } }] }],
            }],
        });
        let config =
            crate::config::parse_config(crate::config::Format::Json, config.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}", e.pointer, e.message))
                .value;
        let (plan, _) =
            crate::plan::compile::compile(&config, &crate::plan::compile::FileSystem, 1)
                .unwrap_or_else(|d| panic!("{d:?}"));
        let listener = plan.listeners[0].key;
        let generation = Generation::standalone(plan, None, Arc::default());
        let (core, epoch) = {
            let _entered = rt.enter();
            let core = Rc::new(Core::new(0, &generation));
            let epoch = (core.clock.unix.get(), tokio::time::Instant::now());
            (core, epoch)
        };
        Server {
            rt,
            core,
            listener,
            epoch,
        }
    }

    /// Serves one connection: writes `pieces` one at a time, each once the driver has had
    /// the chance to act on the one before, then half-closes when `close`; returns what the
    /// driver wrote until it closed.
    fn serve(&self, proto: Proto, pieces: &[&[u8]], close: bool) -> Vec<u8> {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        theirs.set_nonblocking(true).unwrap();
        let info = ConnInfo {
            remote: "192.0.2.1:5000".parse().unwrap(),
            local_port: 1,
            scheme: Scheme::Http,
            proto,
            listener: self.listener,
        };
        self.rt.block_on(async {
            let io = Transport::Plain(Socket::from_fd(OwnedFd::from(ours)).unwrap());
            let core = self.core.clone();
            let driver: Pin<Box<dyn Future<Output = ()>>> = match proto {
                Proto::H2 => Box::pin(crate::proto::h2::serve(core, io, info)),
                _ => Box::pin(crate::proto::h1::server::serve(core, io, info)),
            };
            let (mut rx, mut tx) = tokio::net::UnixStream::from_std(theirs)
                .unwrap()
                .into_split();
            let client = async move {
                for piece in pieces {
                    if tx.write_all(piece).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                if close {
                    let _ = tx.shutdown().await;
                }
                tx
            };
            let reader = async move {
                let mut out = Vec::new();
                let _ = rx.read_to_end(&mut out).await;
                out
            };
            let served = tokio::time::timeout(HANG, async {
                let ((), tx, out) = tokio::join!(driver, client, reader);
                drop(tx);
                out
            });
            let (unix, start) = self.epoch;
            let clock = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let elapsed = start.elapsed().as_secs() as i64;
                    self.core.clock.unix.set(unix + elapsed);
                }
            };
            tokio::select! {
                out = served => out.expect("the connection ends"),
                () = clock => unreachable!("the clock runs forever"),
            }
        })
    }
}

/// A request head the origin reads; the origin answers by what the path holds.
async fn origin(mut sock: tokio::net::TcpStream) {
    let limits = Limits {
        max_head_bytes: 1 << 20,
        max_header_fields: 256,
    };
    let mut head = crate::msg::RequestHead::new();
    let mut buf = Vec::new();
    loop {
        let (framing, upgrade, expect) = loop {
            match codec::parse_request(&buf, &limits, &mut head) {
                Ok(Parsed::Complete {
                    head_len,
                    framing,
                    extra,
                }) => {
                    buf.drain(..head_len);
                    break (framing, extra.upgrade, extra.expect_continue);
                }
                Ok(Parsed::Partial) => {
                    if sock.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                }
                Err(_) => return,
            }
        };
        assert!(!expect, "Expect is not forwarded");
        let path = head.path().as_bytes().to_vec();
        let has = |word: &[u8]| path.windows(word.len()).any(|w| w == word);
        if has(b"early") {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 413 Too Large\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
            return;
        }
        // The request body, read and dropped.
        let mut received = 0u64;
        match framing {
            Framing::Length(mut left) => {
                while left > 0 {
                    if buf.is_empty() && sock.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let take = buf.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    buf.drain(..take);
                    left -= take as u64;
                    received += take as u64;
                }
            }
            Framing::Chunked => {
                let mut chunked = Chunked::default();
                loop {
                    match chunked.scan(&buf) {
                        Ok(Scan::End(n)) => {
                            buf.drain(..n);
                            received += n as u64;
                            break;
                        }
                        Ok(Scan::More) => {
                            received += buf.len() as u64;
                            buf.clear();
                            if sock.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
            Framing::None | Framing::UntilClose => {}
        }
        let body = format!("{received} {}\n", String::from_utf8_lossy(&path));
        let answer = if upgrade {
            "HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n"
                .to_owned()
        } else if has(b"chunk") {
            format!(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\nx-trailer: 1\r\n\r\n",
                body.len()
            )
        } else if has(b"close") {
            format!("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{body}")
        } else if has(b"big") {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                70_000,
                "z".repeat(70_000)
            )
        } else if has(b"304") {
            "HTTP/1.1 304 Not Modified\r\netag: \"e\"\r\n\r\n".to_owned()
        } else if has(b"short") {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{body}",
                body.len() + 10
            )
        } else {
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\ncontent-type: text/plain\r\n\r\n{body}",
                body.len()
            )
        };
        if sock.write_all(answer.as_bytes()).await.is_err() {
            return;
        }
        if upgrade {
            // The tunnel echoes until the proxy closes it.
            let _ = sock.write_all(&buf).await;
            let mut chunk = [0u8; 4096];
            while let Ok(n @ 1..) = sock.read(&mut chunk).await {
                if sock.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
            }
            return;
        }
        if has(b"close") || has(b"short") {
            return;
        }
    }
}

/// Fuzz entry: a client's bytes on an HTTP/1.1 connection. The first byte says whether the
/// client half-closes at the end (bit 0 clear) or keeps its side open, and the size of the
/// pieces the rest arrives in (bit 1 set: `1 + (byte >> 2) * 17` bytes, else one piece).
///
/// Every connection ends, and what the server wrote is responses to the requests that
/// were sent, in order, as [`codec::harness::check_conversation`] reads them.
pub fn h1_input(data: &[u8]) {
    let Some((&options, stream)) = data.split_first() else {
        return;
    };
    let size = match options & 2 {
        0 => stream.len().max(1),
        _ => 1 + usize::from(options >> 2) * 17,
    };
    let pieces: Vec<&[u8]> = stream.chunks(size).collect();
    let out = SERVER.with(|s| s.serve(Proto::H1, &pieces, options & 1 == 0));
    codec::harness::check_conversation(stream, &out);
}

/// Fuzz entry: a client's HTTP/2 frames after the preface and an empty SETTINGS, as
/// [`h2_frames`](crate::proto::h2::harness::frames_input) cuts them into reads. Bit 0 of the
/// first byte keeps the client's side open at the end.
///
/// Every connection ends, and what the server wrote is whole frames within the client's
/// flow-control windows, as [`crate::proto::h2::harness::check_conversation`] reads them.
pub fn h2_input(data: &[u8]) {
    let Some((&options, mut rest)) = data.split_first() else {
        return;
    };
    let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    preface.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]);
    let mut pieces: Vec<&[u8]> = vec![&preface];
    while let Some((&len, tail)) = rest.split_first() {
        let (read, tail) = tail.split_at(usize::from(len).min(tail.len()));
        pieces.push(read);
        rest = tail;
    }
    let out = SERVER.with(|s| s.serve(Proto::H2, &pieces, options & 1 == 0));
    crate::proto::h2::harness::check_conversation(&pieces[1..], &out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        out.extend_from_slice(&[kind, flags]);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// The frames of `out`, as (type, stream, payload).
    fn frames(mut out: &[u8]) -> Vec<(u8, u32, Vec<u8>)> {
        let mut frames = Vec::new();
        while out.len() >= 9 {
            let len = u32::from_be_bytes([0, out[0], out[1], out[2]]) as usize;
            let stream = u32::from_be_bytes([out[5], out[6], out[7], out[8]]) & !(1 << 31);
            frames.push((out[3], stream, out[9..9 + len].to_vec()));
            out = &out[9 + len..];
        }
        assert!(out.is_empty(), "a whole frame");
        frames
    }

    #[test]
    fn a_stream_the_client_grants_no_window_is_reset_and_the_connection_ends() {
        // The client's preface sets every stream window to 0, acknowledges the server's
        // SETTINGS and asks for a response with a body; then it reads, keeps its side open,
        // and grants nothing.
        let mut block = Vec::new();
        for (name, value) in [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/a"),
            (":authority", "a"),
        ] {
            block.push(0);
            block.push(name.len() as u8);
            block.extend_from_slice(name.as_bytes());
            block.push(value.len() as u8);
            block.extend_from_slice(value.as_bytes());
        }
        let mut preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        preface.extend(frame(4, 0, 0, &[0, 4, 0, 0, 0, 0]));
        let pieces = [preface, frame(4, 1, 0, &[]), frame(1, 0x5, 1, &block)];
        let pieces: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        let out = SERVER.with(|s| s.serve(Proto::H2, &pieces, false));
        let frames = frames(&out);
        const RST_STREAM: u8 = 3;
        const GOAWAY: u8 = 7;
        const CANCEL: [u8; 4] = [0, 0, 0, 8];
        assert!(
            frames.contains(&(RST_STREAM, 1, CANCEL.to_vec())),
            "stream 1 is reset: {frames:?}"
        );
        assert!(
            frames.iter().any(|f| f.0 == GOAWAY),
            "the connection ends with a GOAWAY"
        );
    }
}
