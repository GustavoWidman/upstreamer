//! Access logs: one JSON object per line for every finished request or tunnel of a site with an
//! `accessLog`.
//!
//! # Path of a line
//!
//! 1. The control thread opens every log file of a generation ([`Files::open`]: append mode,
//!    created when missing) at startup and at every reload, so the reload that follows a
//!    logrotate rename starts a new file. A file that cannot be opened is reported in the
//!    reload status and the lines meant for it are counted as dropped.
//! 2. Once the pipeline knows the request's site logs, [`start`] reads the monotonic clock and
//!    formats the request's fields, as received, into the exchange's arena. A site without a
//!    log does neither.
//! 3. Once the response or tunnel is over, the driver calls [`record`] with the status and the
//!    body bytes it sent. The core's [`Writer`] appends the whole line to its buffer for that
//!    file.
//! 4. A buffer goes out in one `write(2)` when it passes [`FLUSH_AT`], on the core's 1 s clock
//!    tick, before the core adopts another generation's files, and when the core stops. A
//!    buffer only ever holds whole lines and the file is in append mode, so lines from
//!    different cores never interleave inside a line.
//! 5. A failed or short write drops the lines it did not write and counts them; the core
//!    warns once a second with the count. Nothing waits for the disk.
//!
//! Steady state per logged request: two monotonic clock reads (vDSO, no syscall), no
//! allocation (the arena and the buffers keep their capacity), and a share of one `write`.
//!
//! # Line
//!
//! ```text
//! {"ts":"2026-11-14T08:49:37.123Z","remote_ip":"192.0.2.1","remote_port":51234,
//!  "host":"example.com","method":"GET","target":"/a?b=1","proto":"HTTP/1.1",
//!  "user_agent":"curl/8.5.0","referer":null,"status":200,"bytes":1234,"duration":0.000412,
//!  "upstream":"127.0.0.1:8080"}
//! ```
//!
//! (one line in the file). Field order is fixed; every field is always present.
//!
//! - `ts`: when the response or tunnel ended, UTC, RFC 3339 with milliseconds.
//! - `remote_ip`, `remote_port`: the peer of the connection.
//! - `host`: the host the site was chosen by (lowercase, without port).
//! - `method`, `target`: as the client sent them (`target` before any rewrite or prefix strip).
//! - `proto`: `HTTP/1.0`, `HTTP/1.1`, `HTTP/2` or `HTTP/3`.
//! - `user_agent`, `referer`: the request's first such field as received, or `null`.
//! - `status`: the status sent; 101 for a tunnel.
//! - `bytes`: body bytes sent after the response head (on HTTP/1.1 as framed on the wire,
//!   chunk syntax included); for a tunnel, the bytes relayed to the client.
//! - `duration`: seconds from the site's choice to the end of the response or tunnel.
//! - `upstream`: the origin (`host:port`) of the last proxy step that ran, or `null`.
//!
//! Strings are JSON strings: `"` and `\` escaped, control bytes as `\u00XX`, each invalid
//! UTF-8 sequence as `�`.

use crate::exchange::{ASpan, Exchange};
use crate::msg::{Status, Version};
use crate::plan::{LogId, UpstreamId, UpstreamPlan};
use crate::runtime::{Core, CoreSnapshot};
use std::cell::{Cell, RefCell};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A buffer is written once it holds this many bytes.
pub(crate) const FLUSH_AT: usize = 32 * 1024;
/// What a buffer reserves on its first line: room past [`FLUSH_AT`] for one more line of
/// ordinary size, so a buffer does not grow in the steady state.
const CAPACITY: usize = 64 * 1024;

/// The open files of one generation's access logs, by [`LogId`].
#[derive(Debug, Default)]
pub(crate) struct Files {
    files: Box<[Option<File>]>,
}

/// A log file that could not be opened.
#[derive(Debug)]
pub(crate) struct OpenFailure {
    pub path: PathBuf,
    pub error: io::Error,
}

impl Files {
    /// Opens `paths` (the plan's `access_logs`) for appending, creating missing files. A path
    /// that fails is reported and stays closed; its lines are dropped until a reload opens it.
    pub fn open(paths: &[PathBuf]) -> (Files, Vec<OpenFailure>) {
        let mut failures = Vec::new();
        let files = paths
            .iter()
            .map(|path| {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o640)
                    .open(path)
                    .map_err(|error| {
                        failures.push(OpenFailure {
                            path: path.clone(),
                            error,
                        })
                    })
                    .ok()
            })
            .collect();
        (Files { files }, failures)
    }

    fn get(&self, log: LogId) -> Option<&File> {
        self.files.get(log.0 as usize)?.as_ref()
    }
}

/// What the pipeline noted about a request of a logging site, until the driver records it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Started {
    log: LogId,
    at: Instant,
    /// The request's fields, formatted, in the exchange's arena.
    request: ASpan,
    upstream: Option<UpstreamId>,
}

impl Started {
    /// A proxy step is forwarding the request to `upstream`.
    pub fn proxied_to(&mut self, upstream: UpstreamId) {
        self.upstream = Some(upstream);
    }
}

/// Starts the record of a request whose site logs to `log`: reads the clock and formats the
/// request's fields into the arena while they are still as the client sent them.
pub(crate) fn start(log: LogId, ex: &mut Exchange) -> Started {
    let at = Instant::now();
    let Exchange {
        req, conn, arena, ..
    } = ex;
    let request = arena.build(|out| {
        let _ = write!(
            out,
            "\"remote_ip\":\"{}\",\"remote_port\":{},\"host\":",
            conn.remote.ip(),
            conn.remote.port()
        );
        push_str(out, req.host());
        out.extend_from_slice(b",\"method\":");
        push_str(out, req.method_bytes());
        out.extend_from_slice(b",\"target\":");
        push_str(out, req.raw_target());
        out.extend_from_slice(b",\"proto\":\"");
        out.extend_from_slice(proto(req.version));
        out.extend_from_slice(b"\",\"user_agent\":");
        let field = |name: &[u8]| req.fields.live().find(|(n, _, _)| *n == name);
        push_opt(out, field(b"user-agent").map(|(_, v, _)| v));
        out.extend_from_slice(b",\"referer\":");
        push_opt(out, field(b"referer").map(|(_, v, _)| v));
    });
    Started {
        log,
        at,
        request,
        upstream: None,
    }
}

/// Records a finished request: `status` sent and `bytes` of body after the head. Called by the
/// driver once the response (or tunnel) is over, with the snapshot the request ran under.
pub(crate) fn record(
    core: &Core,
    snap: &CoreSnapshot,
    ex: &Exchange,
    started: Started,
    status: Status,
    bytes: u64,
) {
    let end = Instant::now();
    let upstream = started
        .upstream
        .map(|id| &snap.plan.upstreams[id.0 as usize]);
    let fields = Line {
        ts: core.clock.wall(end),
        request: ex.arena.get(started.request),
        status,
        bytes,
        duration: end.saturating_duration_since(started.at),
        upstream,
    };
    core.access
        .append(&snap.access, started.log, |out| fields.write(out));
}

/// One line's fields.
struct Line<'a> {
    /// Since the Unix epoch.
    ts: Duration,
    request: &'a [u8],
    status: Status,
    bytes: u64,
    duration: Duration,
    upstream: Option<&'a UpstreamPlan>,
}

impl Line<'_> {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(b"{\"ts\":\"");
        push_ts(out, self.ts);
        out.extend_from_slice(b"\",");
        out.extend_from_slice(self.request);
        let _ = write!(
            out,
            ",\"status\":{},\"bytes\":{},\"duration\":{}.{:06},\"upstream\":",
            self.status.code(),
            self.bytes,
            self.duration.as_secs(),
            self.duration.subsec_micros()
        );
        match self.upstream {
            None => out.extend_from_slice(b"null"),
            Some(up) => {
                out.push(b'"');
                let bracket = up.host.contains(':') && !up.host.starts_with('[');
                if bracket {
                    out.push(b'[');
                }
                push_escaped(out, up.host.as_bytes());
                if bracket {
                    out.push(b']');
                }
                let _ = write!(out, ":{}\"", up.port);
            }
        }
        out.extend_from_slice(b"}\n");
    }
}

/// A core's log buffers: one per file of the generation it serves, holding whole lines.
#[derive(Default)]
pub(crate) struct Writer {
    files: RefCell<Arc<Files>>,
    pending: RefCell<Vec<Vec<u8>>>,
    /// The line of a request that started under an earlier generation's files, written to
    /// those files at once (they are open as long as that request's snapshot lives).
    scratch: RefCell<Vec<u8>>,
    dropped: Cell<u64>,
    writes: Cell<u64>,
}

impl Writer {
    pub fn new(files: Arc<Files>) -> Writer {
        let writer = Writer::default();
        writer.adopt(&files);
        writer
    }

    /// Appends the line `line` writes for `log` of `files`, the files the request ran under.
    fn append(&self, files: &Arc<Files>, log: LogId, line: impl FnOnce(&mut Vec<u8>)) {
        let Some(file) = files.get(log) else {
            self.dropped.set(self.dropped.get() + 1);
            return;
        };
        if !Arc::ptr_eq(files, &self.files.borrow()) {
            let mut scratch = self.scratch.borrow_mut();
            line(&mut scratch);
            self.write(file, &mut scratch);
            return;
        }
        let mut pending = self.pending.borrow_mut();
        let buf = &mut pending[log.0 as usize];
        if buf.capacity() == 0 {
            buf.reserve(CAPACITY);
        }
        line(buf);
        if buf.len() >= FLUSH_AT {
            self.write(file, buf);
        }
    }

    /// Writes what is pending and serves `files` from now on. A no-op for the files it serves.
    pub fn adopt(&self, files: &Arc<Files>) {
        if Arc::ptr_eq(files, &self.files.borrow()) {
            return;
        }
        self.flush();
        *self.files.borrow_mut() = files.clone();
        self.pending
            .borrow_mut()
            .resize_with(files.files.len(), Vec::new);
    }

    /// Writes every buffer that holds a line.
    pub fn flush(&self) {
        let files = self.files.borrow();
        for (i, buf) in self.pending.borrow_mut().iter_mut().enumerate() {
            if let Some(file) = files.get(LogId(i as u16))
                && !buf.is_empty()
            {
                self.write(file, buf);
            }
        }
    }

    /// One `write(2)` of `buf`, which then is empty. The lines it did not write are dropped.
    fn write(&self, mut file: &File, buf: &mut Vec<u8>) {
        self.writes.set(self.writes.get() + 1);
        let lost = match file.write(buf) {
            Ok(n) => &buf[n..],
            Err(_) => &buf[..],
        };
        if !lost.is_empty() {
            let lines = memchr::memchr_iter(b'\n', lost).count() as u64;
            self.dropped.set(self.dropped.get() + lines);
        }
        buf.clear();
    }

    /// Lines dropped since the last call.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.replace(0)
    }

    /// `write(2)` calls so far.
    pub fn writes(&self) -> u64 {
        self.writes.get()
    }
}

impl Drop for Writer {
    /// A stopping core writes what it holds.
    fn drop(&mut self) {
        self.flush();
    }
}

fn proto(version: Version) -> &'static [u8] {
    match version {
        Version::Http10 => b"HTTP/1.0",
        Version::Http11 => b"HTTP/1.1",
        Version::H2 => b"HTTP/2",
        Version::H3 => b"HTTP/3",
    }
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn push_ts(out: &mut Vec<u8>, since_epoch: Duration) {
    let secs = since_epoch.as_secs() as i64;
    let (year, month, day) = crate::runtime::civil(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        s / 3600,
        s / 60 % 60,
        s % 60,
        since_epoch.subsec_millis()
    );
}

fn push_opt(out: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(value) => push_str(out, value),
        None => out.extend_from_slice(b"null"),
    }
}

/// `bytes` as a JSON string, quotes included.
fn push_str(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'"');
    push_escaped(out, bytes);
    out.push(b'"');
}

/// The inside of a JSON string for `bytes`: `"` and `\` escaped, control bytes (and DEL) as
/// `\u00XX`, and each invalid UTF-8 sequence as `�`, so any request bytes make valid JSON.
fn push_escaped(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid().as_bytes();
        let mut from = 0;
        for (i, &b) in valid.iter().enumerate() {
            let escape: &[u8] = match b {
                b'"' => b"\\\"",
                b'\\' => b"\\\\",
                0..0x20 | 0x7f => &[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(b >> 4) as usize],
                    HEX[(b & 15) as usize],
                ],
                _ => continue,
            };
            out.extend_from_slice(&valid[from..i]);
            out.extend_from_slice(escape);
            from = i + 1;
        }
        out.extend_from_slice(&valid[from..]);
        if !chunk.invalid().is_empty() {
            out.extend_from_slice(b"\\ufffd");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ConnInfo, Proto, Scheme};
    use crate::plan::{ListenerKey, ListenerKind, OriginAddr};
    use serde_json::{Value, json};

    fn escaped(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_str(&mut out, bytes);
        out
    }

    fn parsed(bytes: &[u8]) -> String {
        let out = escaped(bytes);
        serde_json::from_slice::<String>(&out)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out)))
    }

    #[test]
    fn strings_escape_quotes_backslashes_and_control_bytes() {
        assert_eq!(escaped(b"plain/path?q=1"), b"\"plain/path?q=1\"");
        assert_eq!(escaped(b"a\"b\\c"), b"\"a\\\"b\\\\c\"");
        assert_eq!(
            escaped(b"\x00\t\n\x1b\x7f"),
            b"\"\\u0000\\u0009\\u000a\\u001b\\u007f\""
        );
        assert_eq!(parsed(b"a\"b\\c\x01"), "a\"b\\c\u{1}");
    }

    #[test]
    fn invalid_utf8_becomes_a_replacement_character_and_valid_utf8_stays() {
        assert_eq!(
            parsed("caf\u{e9} \u{1f600}".as_bytes()),
            "caf\u{e9} \u{1f600}"
        );
        assert_eq!(parsed(b"a\xffb\xc3"), "a\u{fffd}b\u{fffd}");
        assert_eq!(
            parsed(b"\xe2\x82"),
            "\u{fffd}",
            "one truncated sequence, one mark"
        );
    }

    #[test]
    fn timestamps_are_rfc3339_utc_with_milliseconds() {
        let ts = |secs, millis| {
            let mut out = Vec::new();
            push_ts(
                &mut out,
                Duration::from_secs(secs) + Duration::from_millis(millis),
            );
            String::from_utf8(out).unwrap()
        };
        assert_eq!(ts(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(ts(784_111_777, 123), "1994-11-06T08:49:37.123Z");
        assert_eq!(ts(951_782_400, 999), "2000-02-29T00:00:00.999Z");
        assert_eq!(ts(1_798_761_599, 7), "2026-12-31T23:59:59.007Z");
    }

    fn exchange(raw: &[(&str, &str)]) -> Exchange {
        let conn = ConnInfo {
            remote: "[2001:db8::1]:40000".parse().unwrap(),
            local_port: 443,
            scheme: Scheme::Https,
            proto: Proto::H2,
            listener: ListenerKey {
                addr: "[::]:443".parse().unwrap(),
                kind: ListenerKind::Https,
            },
        };
        let mut ex = Exchange::new(conn, 0);
        ex.req
            .set_line(b"GET", b"/api/x?q=\"1\"", Version::H2)
            .unwrap();
        ex.req.set_host(b"App.Example.com:443");
        for (name, value) in raw {
            ex.req.push_field(name.as_bytes(), value.as_bytes());
        }
        ex
    }

    fn line(ex: &Exchange, started: Started, upstream: Option<&UpstreamPlan>) -> (String, Value) {
        let mut out = Vec::new();
        Line {
            ts: Duration::from_millis(784_111_777_123),
            request: ex.arena.get(started.request),
            status: Status::new(502).unwrap(),
            bytes: 1234,
            duration: Duration::from_micros(1_500_042),
            upstream,
        }
        .write(&mut out);
        assert_eq!(out.last(), Some(&b'\n'));
        assert_eq!(memchr::memchr_iter(b'\n', &out).count(), 1, "one line");
        let value = serde_json::from_slice(&out).unwrap();
        (String::from_utf8(out).unwrap(), value)
    }

    #[test]
    fn a_line_holds_every_field_in_order() {
        let mut ex = exchange(&[
            ("User-Agent", "curl/8.5.0"),
            ("Referer", "https://example.com/\x01"),
            ("User-Agent", "second"),
        ]);
        let mut started = start(LogId(0), &mut ex);
        ex.req.strip_prefix(b"/api");
        started.proxied_to(UpstreamId(0));
        let up = UpstreamPlan {
            id: UpstreamId(0),
            host: "::1".into(),
            port: 8080,
            addr: OriginAddr::Name,
            tls: None,
            idle: Duration::from_secs(1),
            max_idle_per_core: 1,
        };
        let (text, value) = line(&ex, started, Some(&up));
        let keys = [
            "ts",
            "remote_ip",
            "remote_port",
            "host",
            "method",
            "target",
            "proto",
            "user_agent",
            "referer",
            "status",
            "bytes",
            "duration",
            "upstream",
        ];
        let at: Vec<usize> = keys
            .iter()
            .map(|k| text.find(&format!("\"{k}\":")).expect(k))
            .collect();
        assert!(at.is_sorted(), "fields in order: {text}");
        assert_eq!(value.as_object().unwrap().len(), keys.len());
        assert_eq!(
            value,
            json!({
                "ts": "1994-11-06T08:49:37.123Z",
                "remote_ip": "2001:db8::1",
                "remote_port": 40000,
                "host": "app.example.com",
                "method": "GET",
                "target": "/api/x?q=\"1\"",
                "proto": "HTTP/2",
                "user_agent": "curl/8.5.0",
                "referer": "https://example.com/\u{1}",
                "status": 502,
                "bytes": 1234,
                "duration": 1.500042,
                "upstream": "[::1]:8080",
            })
        );
    }

    #[test]
    fn absent_fields_and_no_upstream_are_null() {
        let mut ex = exchange(&[]);
        let started = start(LogId(0), &mut ex);
        let (_, value) = line(&ex, started, None);
        assert_eq!(value["user_agent"], Value::Null);
        assert_eq!(value["referer"], Value::Null);
        assert_eq!(value["upstream"], Value::Null);
    }

    fn files(dir: &tempfile::TempDir, names: &[&str]) -> Arc<Files> {
        let paths: Vec<PathBuf> = names.iter().map(|n| dir.path().join(n)).collect();
        let (files, failures) = Files::open(&paths);
        assert!(failures.is_empty(), "{failures:?}");
        Arc::new(files)
    }

    fn text(dir: &tempfile::TempDir, name: &str) -> String {
        std::fs::read_to_string(dir.path().join(name)).unwrap_or_default()
    }

    fn numbered(n: usize) -> impl FnOnce(&mut Vec<u8>) {
        move |out| {
            let _ = writeln!(out, "{{\"n\":{n},\"pad\":\"{}\"}}", "x".repeat(200));
        }
    }

    #[test]
    fn lines_are_written_in_batches_of_whole_lines() {
        let dir = tempfile::tempdir().unwrap();
        let files = files(&dir, &["a.log", "b.log"]);
        let writer = Writer::new(files.clone());
        let lines = 2_000;
        for n in 0..lines {
            writer.append(&files, LogId((n % 2) as u16), numbered(n));
        }
        let before_flush = writer.writes();
        writer.flush();
        let (a, b) = (text(&dir, "a.log"), text(&dir, "b.log"));
        let parsed = |text: &str| -> Vec<u64> {
            text.lines()
                .map(|l| {
                    serde_json::from_str::<Value>(l).unwrap()["n"]
                        .as_u64()
                        .unwrap()
                })
                .collect()
        };
        assert_eq!(parsed(&a), (0..lines as u64).step_by(2).collect::<Vec<_>>());
        assert_eq!(parsed(&b), (1..lines as u64).step_by(2).collect::<Vec<_>>());
        let bytes = a.len() + b.len();
        assert!(
            before_flush <= (bytes / FLUSH_AT) as u64,
            "{before_flush} writes for {bytes} bytes before the flush"
        );
        assert!(writer.writes() <= before_flush + 2);
        assert_eq!(writer.take_dropped(), 0);
    }

    #[test]
    fn a_failed_write_drops_and_counts_its_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("read-only.log");
        std::fs::write(&path, b"").unwrap();
        let files = Arc::new(Files {
            files: Box::new([Some(File::open(&path).unwrap()), None]),
        });
        let writer = Writer::new(files.clone());
        for n in 0..3 {
            writer.append(&files, LogId(0), numbered(n));
        }
        writer.append(&files, LogId(1), numbered(3));
        writer.flush();
        assert_eq!(writer.take_dropped(), 4, "3 failed to write, 1 had no file");
        assert_eq!(writer.take_dropped(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), b"");
    }

    #[test]
    fn adopting_new_files_writes_pending_lines_to_the_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        let old = files(&dir, &["access.log"]);
        let writer = Writer::new(old.clone());
        writer.append(&old, LogId(0), numbered(1));
        std::fs::rename(
            dir.path().join("access.log"),
            dir.path().join("access.log.1"),
        )
        .unwrap();
        let new = files(&dir, &["access.log"]);
        writer.adopt(&new);
        assert_eq!(text(&dir, "access.log.1").lines().count(), 1);
        writer.append(&new, LogId(0), numbered(2));
        writer.append(&old, LogId(0), numbered(3));
        assert_eq!(
            text(&dir, "access.log.1").lines().count(),
            2,
            "a request that began under the old files is written to them at once"
        );
        drop(writer);
        assert_eq!(
            text(&dir, "access.log").lines().count(),
            1,
            "written on drop"
        );
    }
}
