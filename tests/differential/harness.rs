//! A fleet host served twice: by Caddy from its Caddyfile and by upstreamer from the config the
//! NixOS module emits, each with its own fixture origins and its own copy of the static trees.
//! Every probe of the host's corpus goes to both, and each answer becomes an [`Observation`].

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::compare::{Observation, Response};
use super::origin::{self, Shared};
use super::support::{self, Proxy};

pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/differential")
}

/// `corpus/<host>.json`: what one fleet host serves, and the requests replayed against it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Host {
    /// The Caddyfile under `caddy/`.
    pub caddyfile: String,
    /// The emitted upstreamer config under `fleet/`.
    pub upstreamer: String,
    /// Origins by the variable the Caddyfile reads their address from, each with the URL the
    /// fleet config names it by. An `https://` origin speaks TLS.
    pub origins: BTreeMap<String, String>,
    /// Static trees by the variable the Caddyfile reads their directory from.
    #[serde(default)]
    pub trees: BTreeMap<String, Tree>,
    pub sites: Vec<Site>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    /// The directory under `trees/`.
    pub dir: String,
    /// What stands for the tree's path in the emitted config.
    pub placeholder: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Site {
    pub host: String,
    pub probes: Vec<Probe>,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub name: String,
    /// `METHOD request-target`.
    pub request: String,
    /// The Host field, when it is not the site's host.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    /// Sends the body chunked instead of with a Content-Length.
    #[serde(default)]
    pub chunked: bool,
    #[serde(default)]
    pub mode: Mode,
}

#[derive(Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Plain,
    /// An event stream: whether the first event arrives while the origin holds the second.
    Stream,
    /// An upgrade: whether bytes sent after a 101 come back from the echoing origin.
    Upgrade,
}

pub fn load(host: &str) -> Host {
    let path = dir().join("corpus").join(format!("{host}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
}

/// Whether a `caddy` binary is on PATH.
pub fn caddy_available() -> bool {
    match Command::new("caddy").arg("version").output() {
        Ok(output) => output.status.success(),
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => panic!("caddy: {e}"),
    }
}

/// Which server answers.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Side {
    Caddy,
    Upstreamer,
}

/// Everything one side needs running: its origins, trees and server.
struct Running {
    server: Server,
    shared: Arc<Shared>,
    /// Addresses that differ between runs, with what stands for them in observations.
    names: Vec<(String, String)>,
    _trees: tempfile::TempDir,
}

enum Server {
    Caddy(Caddy),
    Upstreamer(Proxy),
}

impl Server {
    fn addr(&self) -> SocketAddr {
        match self {
            Server::Caddy(caddy) => caddy.addr,
            Server::Upstreamer(proxy) => proxy.addr,
        }
    }
}

/// Serves `host` on `side` and replays every probe; returns the observations in corpus order.
/// `edit` changes the emitted upstreamer config before it is served.
pub fn observe(host: &Host, side: Side, edit: &(dyn Fn(&mut Value) + Sync)) -> Vec<Observation> {
    let running = start(host, side, edit);
    let addr = running.server.addr();
    let mut observations = Vec::new();
    for site in &host.sites {
        for probe in &site.probes {
            running.shared.take();
            let response = send(addr, &site.host, probe, &running.shared);
            // An origin records a request once it has read all of it, before it answers.
            let upstream = running.shared.take();
            let observation = Observation::new(response, upstream, &running.names);
            observations.push(observation);
        }
    }
    observations
}

fn start(host: &Host, side: Side, edit: &(dyn Fn(&mut Value) + Sync)) -> Running {
    let shared = Arc::new(Shared::default());
    let trees = tempfile::tempdir().unwrap();
    let mut names = Vec::new();
    let mut env = Vec::new();
    let mut upstream_urls = Vec::new();
    for (var, fleet_url) in &host.origins {
        let tls = fleet_url.starts_with("https://");
        let addr = origin::start(var, tls, shared.clone());
        let url = format!("{}://{addr}", if tls { "https" } else { "http" });
        names.push((addr.to_string(), format!("{{{var}}}")));
        env.push((var.clone(), url.clone()));
        upstream_urls.push((fleet_url.clone(), url));
    }
    let mut tree_paths = Vec::new();
    for (var, tree) in &host.trees {
        let copy = trees.path().join(&tree.dir);
        copy_tree(&dir().join("trees").join(&tree.dir), &copy);
        let path = copy.display().to_string();
        let fragments = copy.join("upstreamer");
        if fragments.is_dir() {
            for entry in std::fs::read_dir(&fragments).unwrap() {
                let file = entry.unwrap().path();
                let text = std::fs::read_to_string(&file).unwrap();
                std::fs::write(&file, text.replace("@out@", &path)).unwrap();
            }
        }
        names.push((path.clone(), format!("{{{var}}}")));
        env.push((var.clone(), path.clone()));
        tree_paths.push((tree.placeholder.clone(), path));
    }

    let server = match side {
        Side::Caddy => Server::Caddy(Caddy::start(
            &dir().join("caddy").join(&host.caddyfile),
            &env,
        )),
        Side::Upstreamer => {
            let path = dir().join("fleet").join(&host.upstreamer);
            let mut text = std::fs::read_to_string(&path).unwrap();
            for (from, to) in upstream_urls.iter().chain(&tree_paths) {
                assert!(text.contains(from.as_str()), "{path:?} never names {from}");
                text = text.replace(from.as_str(), to);
            }
            let mut doc: Value = serde_json::from_str(&text).unwrap();
            edit(&mut doc);
            let mut sites = doc["sites"].take();
            for site in sites.as_array_mut().unwrap() {
                site.as_object_mut().unwrap().remove("tls");
            }
            Server::Upstreamer(Proxy::start(sites))
        }
    };
    names.push((server.addr().to_string(), "{proxy}".to_owned()));
    names.push((
        format!(":{}", server.addr().port()),
        ":{proxy-port}".to_owned(),
    ));
    Running {
        server,
        shared,
        names,
        _trees: trees,
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// `caddy run` on a Caddyfile, with a free loopback port in `PORT`.
struct Caddy {
    child: Child,
    addr: SocketAddr,
    _home: tempfile::TempDir,
}

impl Caddy {
    fn start(caddyfile: &Path, env: &[(String, String)]) -> Caddy {
        let home = tempfile::tempdir().unwrap();
        for attempt in 0.. {
            let addr = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let log = std::fs::File::create(home.path().join("caddy.log")).unwrap();
            let mut child = Command::new("caddy")
                .args(["run", "--adapter", "caddyfile", "--config"])
                .arg(caddyfile)
                .env("PORT", addr.port().to_string())
                .envs(env.iter().map(|(k, v)| (k, v)))
                .env("HOME", home.path())
                .env("XDG_CONFIG_HOME", home.path())
                .env("XDG_DATA_HOME", home.path())
                .stdin(Stdio::null())
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .expect("caddy starts");
            let deadline = Instant::now() + support::PATIENCE;
            let exited = loop {
                if let Ok(Some(_)) = child.try_wait() {
                    break true;
                }
                if TcpStream::connect(addr).is_ok() {
                    break false;
                }
                assert!(Instant::now() < deadline, "caddy never listened on {addr}");
                std::thread::sleep(Duration::from_millis(20));
            };
            if !exited {
                return Caddy {
                    child,
                    addr,
                    _home: home,
                };
            }
            let log = std::fs::read_to_string(home.path().join("caddy.log")).unwrap();
            // Another process may take the port between its release here and Caddy's bind.
            assert!(
                attempt < 3 && log.contains("address already in use"),
                "caddy exited at startup:\n{log}"
            );
        }
        unreachable!()
    }
}

impl Drop for Caddy {
    fn drop(&mut self) {
        let _unused = self.child.kill();
        let _unused = self.child.wait();
    }
}

/// The request bytes of `probe` for a site whose host is `host`.
fn request_bytes(host: &str, probe: &Probe) -> Vec<u8> {
    let (method, target) = probe.request.split_once(' ').expect("METHOD target");
    let mut head = format!("{method} {target} HTTP/1.1\r\n");
    match probe.host.as_deref() {
        Some("") => {}
        Some(other) => head.push_str(&format!("Host: {other}\r\n")),
        None => head.push_str(&format!("Host: {host}\r\n")),
    }
    for (name, value) in &probe.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    let mut bytes = Vec::new();
    match (&probe.body, probe.chunked) {
        (Some(body), false) => {
            head.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
            bytes.extend_from_slice(head.as_bytes());
            bytes.extend_from_slice(body.as_bytes());
        }
        (Some(body), true) => {
            head.push_str("Transfer-Encoding: chunked\r\n\r\n");
            bytes.extend_from_slice(head.as_bytes());
            let (first, second) = body.split_at(body.len() / 2);
            for part in [first, second] {
                bytes.extend_from_slice(format!("{:x}\r\n{part}\r\n", part.len()).as_bytes());
            }
            bytes.extend_from_slice(b"0\r\n\r\n");
        }
        (None, _) => {
            head.push_str("\r\n");
            bytes.extend_from_slice(head.as_bytes());
        }
    }
    bytes
}

/// Sends one probe on a new connection and reads its answer.
fn send(addr: SocketAddr, host: &str, probe: &Probe, shared: &Shared) -> Response {
    let mut wire = Wire::connect(addr);
    let head_only = probe.request.starts_with("HEAD ");
    shared.hold();
    wire.stream.write_all(&request_bytes(host, probe)).unwrap();
    match probe.mode {
        Mode::Plain => {
            wire.fill_until(support::PATIENCE, |buf| complete(buf, head_only));
            wire.response(head_only)
        }
        Mode::Stream => {
            let streamed = wire.fill_until(Duration::from_secs(3), |buf| {
                contains(buf, b"data: one") || complete(buf, head_only)
            });
            shared.release();
            wire.fill_until(support::PATIENCE, |buf| complete(buf, head_only));
            let mut response = wire.response(head_only);
            response.streamed = Some(streamed && contains(&wire.buf, b"data: one"));
            response
        }
        Mode::Upgrade => {
            wire.fill_until(support::PATIENCE, |buf| head_end(buf).is_some());
            let mut response = wire.response(true);
            if response.status == 101 {
                wire.buf.clear();
                wire.stream.write_all(b"ping\r\n").unwrap();
                let echoed =
                    wire.fill_until(Duration::from_secs(5), |buf| contains(buf, b"ping\r\n"));
                response.echoed = Some(echoed);
            }
            response
        }
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Whether `buf` holds a whole response; a response delimited by close is never whole.
fn complete(buf: &[u8], head_only: bool) -> bool {
    let Some(end) = head_end(buf) else {
        return false;
    };
    let head = String::from_utf8_lossy(&buf[..end]);
    let status: u16 = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if head_only || status < 200 || status == 204 || status == 304 {
        return true;
    }
    if let Some(length) = support::header(&head, "content-length") {
        return buf.len() - end >= length.parse::<usize>().unwrap_or(usize::MAX);
    }
    if support::header(&head, "transfer-encoding").is_some() {
        return chunked_end(&buf[end..]);
    }
    false
}

fn chunked_end(mut rest: &[u8]) -> bool {
    loop {
        let Some(line) = rest.windows(2).position(|w| w == b"\r\n") else {
            return false;
        };
        let digits = String::from_utf8_lossy(&rest[..line]);
        let digits = digits.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(digits, 16) else {
            return false;
        };
        rest = &rest[line + 2..];
        if size == 0 {
            return contains(rest, b"\r\n") && rest.ends_with(b"\r\n");
        }
        if rest.len() < size + 2 {
            return false;
        }
        rest = &rest[size + 2..];
    }
}

/// A client connection that keeps every byte it read.
struct Wire {
    stream: TcpStream,
    buf: Vec<u8>,
    closed: bool,
}

impl Wire {
    fn connect(addr: SocketAddr) -> Wire {
        let stream = TcpStream::connect(addr).expect("the server accepts");
        stream.set_nodelay(true).unwrap();
        Wire {
            stream,
            buf: Vec::new(),
            closed: false,
        }
    }

    /// Reads until `done` holds, the peer closes, or `patience` passes. Returns `done`.
    fn fill_until(&mut self, patience: Duration, done: impl Fn(&[u8]) -> bool) -> bool {
        let deadline = Instant::now() + patience;
        let mut chunk = [0u8; 16384];
        while !done(&self.buf) && !self.closed {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            self.stream.set_read_timeout(Some(left)).unwrap();
            match self.stream.read(&mut chunk) {
                Ok(0) => self.closed = true,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break;
                }
                Err(e) if e.kind() == ErrorKind::ConnectionReset => self.closed = true,
                Err(e) => panic!("reading a response: {e}"),
            }
        }
        done(&self.buf)
    }

    fn response(&self, head_only: bool) -> Response {
        let Some(end) = head_end(&self.buf) else {
            return Response::none(&self.buf, self.closed);
        };
        let head = String::from_utf8_lossy(&self.buf[..end]).into_owned();
        let status = head
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let raw = &self.buf[end..];
        let body = if head_only || status < 200 || status == 204 || status == 304 {
            Vec::new()
        } else if let Some(length) = support::header(&head, "content-length") {
            raw[..length.parse::<usize>().unwrap().min(raw.len())].to_vec()
        } else if support::header(&head, "transfer-encoding").is_some() && chunked_end(raw) {
            support::dechunk(raw)
        } else {
            raw.to_vec()
        };
        Response {
            status,
            head,
            body,
            streamed: None,
            echoed: None,
        }
    }
}
