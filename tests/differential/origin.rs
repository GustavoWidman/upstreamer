//! Fixture origins: one blocking server per upstream address of a fleet host, recording every
//! request it reads. What an origin answers depends only on the request, so both proxies meet
//! the same behaviour:
//!
//! - an `Upgrade` request: 101, then every byte read is echoed back;
//! - a path ending in `/live`: an event stream that sends one event, waits for the test to see
//!   it arrive (or 5s), then a second one;
//! - a path containing `/slow`: the answer comes after [`SLOW`];
//! - a path containing `/status/<code>`: that status;
//! - a path containing `/origin-headers`: fields a site also sets or removes;
//! - a path containing `/large`: a 4 KiB compressible body;
//! - otherwise 200 with `<origin>: <request line>` as the body, and `ETag: "o1"`, which an
//!   `If-None-Match: "o1"` turns into a 304.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::support;

/// The ETag of every answer of an origin.
pub const ETAG: &str = "\"o1\"";

/// Longer than the shortest response header timeout of the fleet (15s), shorter than the next
/// (60s).
pub const SLOW: Duration = Duration::from_secs(16);

/// A request as an origin read it. Header names are lowercase.
#[derive(Debug, Clone)]
pub struct Seen {
    pub origin: String,
    pub line: String,
    pub headers: Vec<(String, String)>,
    /// The body's data, chunk syntax removed.
    pub body: Vec<u8>,
}

/// What every origin of one proxy shares: the requests they read, and the event stream's
/// release.
#[derive(Default)]
pub struct Shared {
    seen: Mutex<Vec<Seen>>,
    released: Mutex<bool>,
    release: Condvar,
}

impl Shared {
    /// Takes the requests read since the last call.
    pub fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut self.seen.lock().unwrap())
    }

    pub fn hold(&self) {
        *self.released.lock().unwrap() = false;
    }

    pub fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.release.notify_all();
    }

    fn wait_for_release(&self) {
        let released = self.released.lock().unwrap();
        let _unused = self
            .release
            .wait_timeout_while(released, Duration::from_secs(5), |r| !*r)
            .unwrap();
    }
}

/// Starts an origin named `name`; it speaks TLS (with a self-signed certificate) when `tls`.
pub fn start(name: &str, tls: bool, shared: Arc<Shared>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = tls.then(server_config);
    let name = name.to_owned();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            stream.set_read_timeout(Some(support::PATIENCE)).unwrap();
            let (name, shared, config) = (name.clone(), shared.clone(), config.clone());
            std::thread::spawn(move || match config {
                Some(config) => {
                    let conn = rustls::ServerConnection::new(config).unwrap();
                    serve(rustls::StreamOwned::new(conn, stream), &name, &shared);
                }
                None => serve(stream, &name, &shared),
            });
        }
    });
    addr
}

fn server_config() -> Arc<rustls::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).unwrap();
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn serve<S: Read + Write>(stream: S, name: &str, shared: &Shared) {
    let mut conn = BufReader::new(stream);
    while let Some(seen) = read_request(&mut conn, name) {
        shared.seen.lock().unwrap().push(seen.clone());
        let close = field(&seen, "connection").is_some_and(|v| v.eq_ignore_ascii_case("close"));
        if field(&seen, "upgrade").is_some() {
            upgrade(&mut conn, &seen);
            return;
        }
        if answer(conn.get_mut(), &seen, shared).is_err() || close {
            return;
        }
    }
}

fn field<'a>(seen: &'a Seen, name: &str) -> Option<&'a str> {
    seen.headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

fn read_request<S: Read>(conn: &mut BufReader<S>, name: &str) -> Option<Seen> {
    let mut line = String::new();
    if conn.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut headers = Vec::new();
    loop {
        let mut field = String::new();
        if conn.read_line(&mut field).ok()? == 0 {
            return None;
        }
        let field = field.trim_end_matches(['\r', '\n']);
        if field.is_empty() {
            break;
        }
        let (n, v) = field.split_once(':')?;
        headers.push((n.to_ascii_lowercase(), v.trim().to_owned()));
    }
    let mut seen = Seen {
        origin: name.to_owned(),
        line: line.trim_end().to_owned(),
        headers,
        body: Vec::new(),
    };
    if let Some(length) = field(&seen, "content-length") {
        let mut body = vec![0; length.parse().ok()?];
        conn.read_exact(&mut body).ok()?;
        seen.body = body;
    } else if field(&seen, "transfer-encoding").is_some() {
        seen.body = read_chunked(conn)?;
    }
    Some(seen)
}

fn read_chunked<S: Read>(conn: &mut BufReader<S>) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size = String::new();
        conn.read_line(&mut size).ok()?;
        let digits = size.split([';', '\r', '\n']).next()?;
        let size = usize::from_str_radix(digits.trim(), 16).ok()?;
        if size == 0 {
            loop {
                let mut trailer = String::new();
                conn.read_line(&mut trailer).ok()?;
                if trailer == "\r\n" || trailer.is_empty() {
                    return Some(body);
                }
            }
        }
        let start = body.len();
        body.resize(start + size + 2, 0);
        conn.read_exact(&mut body[start..]).ok()?;
        body.truncate(start + size);
    }
}

fn upgrade<S: Read + Write>(conn: &mut BufReader<S>, seen: &Seen) {
    let protocol = field(seen, "upgrade").unwrap_or_default();
    let mut head = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {protocol}\r\nConnection: Upgrade\r\n"
    );
    if let Some(key) = field(seen, "sec-websocket-key") {
        let accept = support::websocket_accept(key);
        head.push_str(&format!("Sec-WebSocket-Accept: {accept}\r\n"));
    }
    head.push_str("\r\n");
    if conn.get_mut().write_all(head.as_bytes()).is_err() {
        return;
    }
    let _unused = conn.get_mut().flush();
    loop {
        let bytes = match conn.fill_buf() {
            Ok([]) | Err(_) => return,
            Ok(bytes) => bytes.to_vec(),
        };
        conn.consume(bytes.len());
        if conn.get_mut().write_all(&bytes).is_err() {
            return;
        }
        let _unused = conn.get_mut().flush();
    }
}

fn answer<S: Write>(out: &mut S, seen: &Seen, shared: &Shared) -> std::io::Result<()> {
    let mut words = seen.line.split(' ');
    let method = words.next().unwrap_or_default();
    let target = words.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();

    if path.ends_with("/live") {
        let event = |data: &str| {
            let event = format!("data: {data}\n\n");
            format!("{:x}\r\n{event}\r\n", event.len())
        };
        out.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\
                 Transfer-Encoding: chunked\r\n\r\n{}",
                event("one")
            )
            .as_bytes(),
        )?;
        out.flush()?;
        shared.wait_for_release();
        out.write_all(format!("{}0\r\n\r\n", event("two")).as_bytes())?;
        return out.flush();
    }
    if path.contains("/slow") {
        std::thread::sleep(SLOW);
    }

    let mut status = "200 OK".to_owned();
    let mut fields = vec![
        ("Content-Type", "text/plain; charset=utf-8".to_owned()),
        ("ETag", ETAG.to_owned()),
        ("X-Origin", seen.origin.clone()),
    ];
    let mut body = format!("{}: {}\n", seen.origin, seen.line).into_bytes();
    if let Some(code) = path.split("/status/").nth(1) {
        status = format!("{} Origin Says", &code[..3.min(code.len())]);
    }
    if path.contains("/origin-headers") {
        fields.extend([
            ("X-Frame-Options", "ALLOWALL".to_owned()),
            ("Cache-Control", "no-store".to_owned()),
            ("Server", "origin".to_owned()),
            ("Vary", "Origin".to_owned()),
            ("Set-Cookie", "s=1; Path=/; HttpOnly".to_owned()),
        ]);
    }
    if path.contains("/large") {
        body = "Each event the server keeps is written once and read many times. "
            .repeat(64)
            .into_bytes();
    }
    if field(seen, "if-none-match") == Some(ETAG) {
        status = "304 Not Modified".to_owned();
        body.clear();
    }
    let mut head = format!("HTTP/1.1 {status}\r\n");
    for (name, value) in &fields {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let bodiless = status.starts_with("304") || status.starts_with("204");
    if !bodiless {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    out.write_all(head.as_bytes())?;
    if method != "HEAD" && !bodiless {
        out.write_all(&body)?;
    }
    out.flush()
}
