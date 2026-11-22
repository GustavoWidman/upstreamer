//! Shared by the end-to-end tests: the real `upstreamer` binary serving a JSON config on a
//! loopback port, origins that are threads with blocking sockets, and a raw HTTP/1.1 client
//! that shows the bytes on the wire.

#![allow(dead_code)]

pub mod clients;

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// How long a test waits for anything before it fails.
pub const PATIENCE: Duration = Duration::from_secs(20);

/// A running `upstreamer run`, stopped with SIGTERM when dropped.
pub struct Proxy {
    child: Child,
    pub addr: SocketAddr,
    /// The notification that said the proxy was ready.
    pub ready: String,
    config: PathBuf,
    /// The socket the proxy is asked to reload on (`upstreamer reload --reload-socket`).
    pub reload_socket: PathBuf,
    notify: UnixDatagram,
    _port: Reserved,
    _dir: tempfile::TempDir,
}

/// One site for every host, made of `routes`.
pub fn site(routes: Value) -> Value {
    json!([{ "name": "test", "hosts": ["*"], "routes": routes }])
}

impl Proxy {
    /// Starts the proxy with `sites` on a free loopback port, two cores.
    pub fn start(sites: Value) -> Proxy {
        Proxy::start_with(sites, json!({}))
    }

    /// Like [`Proxy::start`], with more top-level config keys (`timeouts`, `limits`,
    /// `workers`).
    pub fn start_with(sites: Value, top: Value) -> Proxy {
        Proxy::start_program(env!("CARGO_BIN_EXE_upstreamer").as_ref(), sites, top)
    }

    /// Like [`Proxy::start_with`], running the program file at `binary`.
    pub fn start_program(binary: &std::path::Path, sites: Value, top: Value) -> Proxy {
        let dir = tempfile::tempdir().unwrap();
        let port = Reserved::new();
        let addr = port.addr;
        let config = dir.path().join("config.json");
        std::fs::write(&config, document(addr, sites, top).to_string()).unwrap();
        let reload_socket = dir.path().join("reload");
        let notify_path = dir.path().join("notify");
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        notify
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        // `UPSTREAMER_WRAP="strace -f -c -o counts"` runs the proxy under another program.
        // The proxy gets a process group of its own, so signals reach it through a wrapper.
        let wrap = std::env::var("UPSTREAMER_WRAP").unwrap_or_default();
        let mut words = wrap
            .split_whitespace()
            .map(std::ffi::OsStr::new)
            .chain([binary.as_os_str()]);
        let mut command = Command::new(words.next().unwrap());
        let mut child = command
            .args(words)
            .arg("run")
            .arg(&config)
            .arg("--reload-socket")
            .arg(&reload_socket)
            .env("NOTIFY_SOCKET", &notify_path)
            .stdin(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("the upstreamer binary starts");
        let deadline = Instant::now() + PATIENCE;
        let mut buf = [0u8; 4096];
        let ready = loop {
            if let Ok(n) = notify.recv(&mut buf) {
                break String::from_utf8_lossy(&buf[..n]).into_owned();
            }
            if let Ok(Some(status)) = child.try_wait() {
                panic!("upstreamer exited at startup: {status}");
            }
            assert!(Instant::now() < deadline, "upstreamer never became ready");
        };
        assert!(ready.starts_with("READY=1"), "{ready}");
        notify.set_read_timeout(Some(PATIENCE)).unwrap();
        Proxy {
            child,
            addr,
            ready,
            config,
            reload_socket,
            notify,
            _port: port,
            _dir: dir,
        }
    }

    /// The next systemd notification the proxy sent.
    pub fn notification(&self) -> String {
        let mut buf = [0u8; 4096];
        let n = self.notify.recv(&mut buf).expect("a notification");
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    /// Sends SIGHUP and waits for the reload to finish; returns its `STATUS=`.
    pub fn reload(&self) -> String {
        self.signal(libc::SIGHUP);
        let reloading = self.notification();
        assert!(reloading.starts_with("RELOADING=1"), "{reloading}");
        let ready = self.notification();
        let status = ready.strip_prefix("READY=1\nSTATUS=").expect("a status");
        status.to_owned()
    }

    /// Replaces the config file's sites; takes effect at the next [`Proxy::reload`].
    pub fn rewrite(&self, sites: Value) {
        self.rewrite_with(sites, json!({}));
    }

    /// Replaces the config file's sites and top-level keys, as [`Proxy::start_with`] takes them.
    pub fn rewrite_with(&self, sites: Value, top: Value) {
        self.rewrite_raw(document(self.addr, sites, top).to_string().as_bytes());
    }

    /// Replaces the config file with `bytes`, as an atomic rename.
    pub fn rewrite_raw(&self, bytes: &[u8]) {
        let temp = self.config.with_extension("new");
        std::fs::write(&temp, bytes).unwrap();
        std::fs::rename(temp, &self.config).unwrap();
    }

    /// Waits up to `limit` for the proxy to exit; `None` if it is still running.
    pub fn exit_within(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The process id of the proxy as it was started.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn signal(&self, signal: libc::c_int) {
        // SAFETY: signals the process group of the child this test started and has not
        // waited for.
        assert_eq!(unsafe { libc::kill(-(self.child.id() as i32), signal) }, 0);
    }

    pub fn client(&self) -> Client {
        Client::connect(self.addr)
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // A test that stopped the proxy itself leaves no process group to signal.
        // SAFETY: as in `signal`; a failure only means the group is gone.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn document(addr: SocketAddr, sites: Value, top: Value) -> Value {
    let mut doc = json!({
        "version": 1,
        "workers": 2,
        "listen": { "http": [addr], "https": [] },
        "timeouts": { "shutdown": "1s" },
        "sites": sites,
    });
    for (key, value) in top.as_object().into_iter().flatten() {
        doc[key] = value.clone();
    }
    doc
}

/// A loopback port held by a socket that is bound and never listens. While it lives no
/// other socket is given the port by the kernel, and the proxy can still bind it (it sets
/// SO_REUSEPORT, as this socket does).
pub struct Reserved {
    pub addr: SocketAddr,
    _socket: socket2::Socket,
}

impl Reserved {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Reserved {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.set_reuse_port(true).unwrap();
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        socket.bind(&any.into()).unwrap();
        let addr = socket.local_addr().unwrap().as_socket().unwrap();
        Reserved {
            addr,
            _socket: socket,
        }
    }
}

/// A loopback address where connections are refused: its port was free a moment ago.
pub fn closed_addr() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// An origin server: every accepted connection gets its own thread running `serve`.
pub struct Origin {
    pub addr: SocketAddr,
    accepted: Arc<AtomicUsize>,
}

impl Origin {
    /// `serve` gets the connection and its index, counted from 0 in accept order.
    pub fn start(serve: impl Fn(TcpStream, usize) + Send + Sync + 'static) -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let serve = Arc::new(serve);
        std::thread::spawn({
            let accepted = accepted.clone();
            move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    stream.set_read_timeout(Some(PATIENCE)).unwrap();
                    let index = accepted.fetch_add(1, Ordering::SeqCst);
                    let serve = serve.clone();
                    std::thread::spawn(move || serve(stream, index));
                }
            }
        });
        Origin { addr, accepted }
    }

    /// An origin that answers every request with what `answer` returns, keep-alive.
    pub fn answering(answer: impl Fn(&Request) -> Vec<u8> + Send + Sync + 'static) -> Origin {
        Origin::start(move |stream, _| {
            let mut conn = Client::over(stream);
            while let Some(request) = conn.request() {
                if conn.send(&answer(&request)).is_err() {
                    return;
                }
            }
        })
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Connections accepted so far.
    pub fn connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

/// A request as an origin read it.
#[derive(Debug, Clone)]
pub struct Request {
    /// Request line and fields, with the empty line.
    pub head: String,
    /// The body as it was on the wire: chunk syntax included for a chunked body.
    pub body: Vec<u8>,
}

impl Request {
    pub fn line(&self) -> &str {
        self.head.lines().next().unwrap_or_default()
    }
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.head, name)
    }
}

/// A response as a client read it.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Status line and fields, with the empty line.
    pub head: String,
    /// The body's data: chunk syntax removed from a chunked body.
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.head, name)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// The first field named `name` (any case) of a head.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (field, value) = line.split_once(':')?;
        field.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// One end of an HTTP/1.1 connection over a blocking socket, for tests' clients and origins.
pub struct Client {
    reader: BufReader<TcpStream>,
}

impl Client {
    pub fn connect(addr: SocketAddr) -> Client {
        let stream = TcpStream::connect(addr).expect("the proxy accepts");
        stream.set_read_timeout(Some(PATIENCE)).unwrap();
        stream.set_nodelay(true).unwrap();
        Client::over(stream)
    }

    pub fn over(stream: TcpStream) -> Client {
        Client {
            reader: BufReader::new(stream),
        }
    }

    pub fn stream(&self) -> &TcpStream {
        self.reader.get_ref()
    }

    pub fn send(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.reader.get_mut().write_all(bytes)
    }

    /// Sends a request and reads its response.
    pub fn roundtrip(&mut self, request: &str) -> Response {
        self.send(request.as_bytes()).unwrap();
        let head_only = request.starts_with("HEAD ");
        self.response(head_only).expect("a response")
    }

    /// `GET path` with `Host: test`, keep-alive.
    pub fn get(&mut self, path: &str) -> Response {
        self.roundtrip(&format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n"))
    }

    /// Reads a head: everything up to and including the empty line. `None` when the peer
    /// closed before sending any byte.
    pub fn head(&mut self) -> Option<String> {
        let mut head = String::new();
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) if head.is_empty() => return None,
                Ok(0) => panic!("the peer closed inside a head: {head:?}"),
                Ok(_) => {}
                Err(e) if head.is_empty() && e.kind() == std::io::ErrorKind::ConnectionReset => {
                    return None;
                }
                Err(e) => panic!("reading a head after {head:?}: {e}"),
            }
            head.push_str(&line);
            if line == "\r\n" {
                return Some(head);
            }
        }
    }

    /// Reads one line, with its line end.
    pub fn head_line(&mut self) -> String {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("a line arrives");
        line
    }

    /// Reads exactly `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut bytes = vec![0; n];
        self.reader
            .read_exact(&mut bytes)
            .expect("the bytes arrive");
        bytes
    }

    /// Reads to the end of the stream.
    pub fn rest(&mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self.reader.read_to_end(&mut bytes) {
            Ok(_) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => bytes,
            Err(e) => panic!("reading to the end: {e}"),
        }
    }

    /// Whether the peer closed: the next read returns end of stream (or a reset).
    pub fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        match self.reader.read(&mut byte) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => e.kind() == std::io::ErrorKind::ConnectionReset,
        }
    }

    /// Reads a chunked body to its end and returns it as it was on the wire.
    pub fn chunked_raw(&mut self) -> Vec<u8> {
        let mut raw = Vec::new();
        loop {
            let mut line = Vec::new();
            self.reader.read_until(b'\n', &mut line).unwrap();
            assert!(line.ends_with(b"\r\n"), "a chunk size line: {line:?}");
            let digits = line.split(|&b| b == b';' || b == b'\r').next().unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(digits).unwrap().trim(), 16)
                .expect("a chunk size");
            raw.extend_from_slice(&line);
            if size == 0 {
                loop {
                    let mut trailer = Vec::new();
                    self.reader.read_until(b'\n', &mut trailer).unwrap();
                    raw.extend_from_slice(&trailer);
                    if trailer == b"\r\n" {
                        return raw;
                    }
                }
            }
            raw.extend_from_slice(&self.bytes(size + 2));
        }
    }

    /// Reads one response. `head_only`: the request was a HEAD.
    pub fn response(&mut self, head_only: bool) -> Option<Response> {
        let head = self.head()?;
        let status: u16 = head
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("a status line: {head:?}"));
        let bodiless = head_only || status < 200 || status == 204 || status == 304;
        let body = if bodiless {
            Vec::new()
        } else if let Some(length) = header(&head, "content-length") {
            self.bytes(length.parse().expect("a length"))
        } else if header(&head, "transfer-encoding").is_some() {
            dechunk(&self.chunked_raw())
        } else {
            self.rest()
        };
        Some(Response { status, head, body })
    }

    /// Reads one request, as an origin. `None` when the peer closed between requests.
    pub fn request(&mut self) -> Option<Request> {
        let head = self.head()?;
        let body = if let Some(length) = header(&head, "content-length") {
            self.bytes(length.parse().expect("a length"))
        } else if header(&head, "transfer-encoding").is_some() {
            self.chunked_raw()
        } else {
            Vec::new()
        };
        Some(Request { head, body })
    }
}

/// The data of a chunked body.
pub fn dechunk(raw: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut rest = raw;
    loop {
        let line_end = rest.windows(2).position(|w| w == b"\r\n").unwrap();
        let digits = rest[..line_end].split(|&b| b == b';').next().unwrap();
        let size = usize::from_str_radix(std::str::from_utf8(digits).unwrap().trim(), 16).unwrap();
        if size == 0 {
            return data;
        }
        let start = line_end + 2;
        data.extend_from_slice(&rest[start..start + size]);
        rest = &rest[start + size + 2..];
    }
}

/// A response with a body and a Content-Length, keep-alive.
pub fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Lowercase hex SHA-256.
pub fn sha256(bytes: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// `len` bytes that do not repeat with a short period.
pub fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Runs `curl` with `args`. `None` when no curl is installed: the caller skips its test.
pub fn curl(args: &[&str]) -> Option<Output> {
    match Command::new("curl")
        .args(["--silent", "--show-error", "--max-time", "20"])
        .args(args)
        .output()
    {
        Ok(output) => Some(output),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipped: curl is not installed");
            None
        }
        Err(e) => panic!("curl: {e}"),
    }
}

/// Polls `condition` until it holds; panics with `what` after [`PATIENCE`].
pub fn eventually(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while !condition() {
        assert!(Instant::now() < deadline, "never happened: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key` (RFC 6455 §4.2.2).
pub fn websocket_accept(key: &str) -> String {
    let mut input = key.as_bytes().to_vec();
    input.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
    base64(digest.as_ref())
}

pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for group in bytes.chunks(3) {
        let n = group
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= group.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A WebSocket frame with the FIN bit, masked when `mask` is given (clients mask).
pub fn websocket_frame(opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    assert!(payload.len() < 126, "short frames only");
    let mut frame = vec![
        0x80 | opcode,
        payload.len() as u8 | if mask.is_some() { 0x80 } else { 0 },
    ];
    match mask {
        Some(mask) => {
            frame.extend_from_slice(&mask);
            frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        }
        None => frame.extend_from_slice(payload),
    }
    frame
}

/// Reads one short WebSocket frame: (opcode, unmasked payload).
pub fn read_websocket_frame(conn: &mut Client) -> (u8, Vec<u8>) {
    let header = conn.bytes(2);
    let len = usize::from(header[1] & 0x7f);
    assert!(len < 126, "short frames only");
    let mask = (header[1] & 0x80 != 0).then(|| conn.bytes(4));
    let mut payload = conn.bytes(len);
    if let Some(mask) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    (header[0] & 0x0f, payload)
}
