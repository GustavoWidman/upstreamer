//! Asking a running process to reload, and learning what came of it.
//!
//! A SIGHUP reloads and tells its sender nothing. `upstreamer reload` asks over a Unix socket
//! the running process listens on (`run --reload-socket`), waits until the reload is done, and
//! exits with what came of it. As a unit's `ExecReload=` that is what makes `systemctl reload`
//! fail when the reload did, and with it whatever ran it.
//!
//! One JSON object per line:
//!
//! ```text
//! server  {"versions":[1]}                                    once a connection is accepted
//! client  {"version":1,"request":"reload"}
//! server  {"result":"done","status":"serving generation 7"}   the reload is done
//!       | {"result":"failed","reason":"..."}                  it was tried; what ran still runs
//!       | {"result":"refused","reason":"..."}                 nothing was tried
//! ```
//!
//! The two ends are often two versions of this program: the client is the program file at the
//! start path, the server the process started from the file that was there before. The
//! greeting is what every version shares: one line, an object with `versions`, the protocol
//! versions the server speaks. The client names the highest one it speaks too, and everything
//! after the greeting belongs to that version. A reader ignores a field it does not know. A
//! client that speaks none of the server's versions asks nothing ([`ReloadError::Incompatible`]).
//!
//! The server answers one client at a time, and a reload runs between a request and its
//! answer. A client that connects meanwhile waits in the socket's queue, which a process that
//! takes over inherits with the socket ([`Listener::share`]), so it is answered by whichever
//! process is the main one by then.

use crate::log::warning;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// The protocol versions this build speaks.
const VERSIONS: &[u32] = &[1];

/// How long a client that connected has to send its request, and to take the answer.
const REQUEST_PATIENCE: Duration = Duration::from_secs(5);

/// The longest request line a server reads.
const REQUEST_LIMIT: usize = 1024;

/// How long a client waits for the whole exchange: a handover under way when it connects and
/// its own, each at most [`super::handover::READY_TIMEOUT`], and a margin.
pub(crate) const PATIENCE: Duration = Duration::from_secs(75);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Greeting {
    versions: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Request {
    version: u32,
    request: String,
}

/// The one request of version 1.
const RELOAD: &str = "reload";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "camelCase")]
enum Reply {
    /// The reload is done: the status of the process that serves now.
    Done { status: String },
    /// The reload was tried and what ran before still runs.
    Failed { reason: String },
    /// The request was not one this server acts on.
    Refused { reason: String },
}

impl Reply {
    /// The answer to a reload that ended with a status line, or with the reason it changed
    /// nothing.
    fn of(outcome: &Result<String, String>) -> Reply {
        match outcome {
            Ok(status) => Reply::Done {
                status: status.clone(),
            },
            Err(reason) => Reply::Failed {
                reason: reason.clone(),
            },
        }
    }
}

fn line<T: Serialize>(message: &T) -> Vec<u8> {
    let mut line = serde_json::to_vec(message).expect("a message is a JSON object");
    line.push(b'\n');
    line
}

/// Checks a request line; the error is the reason it is refused.
fn admit(line: &[u8]) -> Result<(), String> {
    let request: Request =
        serde_json::from_slice(line).map_err(|e| format!("not a request: {e}"))?;
    if !VERSIONS.contains(&request.version) {
        return Err(format!(
            "version {} is not one this process speaks ({})",
            request.version,
            list(VERSIONS)
        ));
    }
    if request.request != RELOAD {
        return Err(format!("unknown request {:?}", request.request));
    }
    Ok(())
}

fn list(versions: &[u32]) -> String {
    let versions: Vec<String> = versions.iter().map(u32::to_string).collect();
    versions.join(", ")
}

/// Where a process is asked to reload.
pub(crate) enum Source {
    /// A path to listen at.
    Bind(PathBuf),
    /// The listening socket of the process this one takes over from.
    Inherited(OwnedFd),
}

/// The socket a running process is asked on.
pub(crate) struct Listener {
    listener: tokio::net::UnixListener,
    /// How long a client that connected has to send its request.
    patience: Duration,
    /// The connection whose request is being read. It lives here, not in [`Listener::next`],
    /// so that `next` can be dropped between two reads and called again.
    pending: Option<Pending>,
}

struct Pending {
    stream: tokio::net::UnixStream,
    read: Vec<u8>,
    deadline: tokio::time::Instant,
}

/// A client that asked for a reload and waits for what comes of it.
pub(crate) struct Asker {
    stream: tokio::net::UnixStream,
}

impl Listener {
    /// Listens as `source` says. Must run inside a tokio runtime.
    pub fn open(source: Source) -> io::Result<Listener> {
        let socket = match source {
            Source::Bind(path) => bind(&path)?,
            Source::Inherited(fd) => {
                let socket = socket2::Socket::from(fd);
                socket.set_cloexec(true)?;
                socket
            }
        };
        socket.set_nonblocking(true)?;
        let listener = std::os::unix::net::UnixListener::from(OwnedFd::from(socket));
        Ok(Listener {
            listener: tokio::net::UnixListener::from_std(listener)?,
            patience: REQUEST_PATIENCE,
            pending: None,
        })
    }

    /// Another descriptor of the socket, for a process that takes over: what queues on the
    /// socket is then that process's to accept.
    pub fn share(&self) -> io::Result<OwnedFd> {
        self.listener.as_fd().try_clone_to_owned()
    }

    /// The next client that asks for a reload. A client that asks for anything else, or for
    /// nothing in time, is refused and the next one awaited.
    ///
    /// Cancel safe: dropped and called again, it goes on with the connection it had.
    pub async fn next(&mut self) -> Asker {
        loop {
            if self.pending.is_none() {
                match self.listener.accept().await {
                    Ok((stream, _)) => self.pending = Pending::greet(stream, self.patience),
                    Err(e) => {
                        warning!("reload socket: {e}");
                        // Out of descriptors, most likely: not a loop that spins.
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                continue;
            }
            let Some(request) = self.read().await else {
                self.pending = None;
                continue;
            };
            let Pending { stream, .. } = self.pending.take().expect("a request was read");
            match admit(&request) {
                Ok(()) => return Asker { stream },
                Err(reason) => Asker { stream }.send(&Reply::Refused { reason }).await,
            }
        }
    }

    /// Reads the pending connection's request line. `None` when the client went away, sent
    /// more than a request, or sent none in time.
    async fn read(&mut self) -> Option<Vec<u8>> {
        let pending = self.pending.as_mut()?;
        loop {
            if let Some(end) = pending.read.iter().position(|&byte| byte == b'\n') {
                return Some(pending.read[..end].to_vec());
            }
            if pending.read.len() > REQUEST_LIMIT {
                return None;
            }
            // Waiting for readiness reads nothing, so nothing is lost when this is dropped.
            tokio::time::timeout_at(pending.deadline, pending.stream.readable())
                .await
                .ok()?
                .ok()?;
            let mut chunk = [0u8; 256];
            match pending.stream.try_read(&mut chunk) {
                Ok(0) => return None,
                Ok(n) => pending.read.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return None,
            }
        }
    }
}

impl Pending {
    /// Sends the greeting. `None` when it cannot be written at once, which the empty buffer
    /// of a connection just accepted rules out while its client is there.
    fn greet(stream: tokio::net::UnixStream, patience: Duration) -> Option<Pending> {
        let greeting = line(&Greeting {
            versions: VERSIONS.to_vec(),
        });
        match stream.try_write(&greeting) {
            Ok(n) if n == greeting.len() => Some(Pending {
                stream,
                read: Vec::new(),
                deadline: tokio::time::Instant::now() + patience,
            }),
            _ => None,
        }
    }
}

impl Asker {
    /// Tells the client what came of the reload: its status line, or why it changed nothing.
    pub async fn answer(self, outcome: &Result<String, String>) {
        self.send(&Reply::of(outcome)).await;
    }

    async fn send(mut self, reply: &Reply) {
        use tokio::io::AsyncWriteExt;
        // A client that left, or that does not read, does not learn the outcome; the log and
        // the status have it.
        let line = line(reply);
        let _ = tokio::time::timeout(REQUEST_PATIENCE, self.stream.write_all(&line)).await;
    }
}

/// A listening socket at `path`, for its owner alone. A socket file nothing listens on is what
/// a process that is gone left behind, and is replaced; any other file is left alone.
fn bind(path: &Path) -> io::Result<socket2::Socket> {
    let addr = socket2::SockAddr::unix(path)?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    match socket.bind(&addr) {
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            if !std::fs::symlink_metadata(path)?.file_type().is_socket() {
                return Err(io::Error::other("a file that is not a socket is there"));
            }
            match UnixStream::connect(path) {
                Ok(_) => return Err(io::Error::other("another process listens there")),
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(e),
            }
            std::fs::remove_file(path)?;
            socket.bind(&addr)?;
        }
        bound => bound?,
    }
    // Nothing connects before `listen`, so the mode is in place before the first client.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    socket.listen(16)?;
    Ok(socket)
}

/// Why asking for a reload did not end with the reload done.
#[derive(Debug, PartialEq, Eq)]
pub enum ReloadError {
    /// The running process tried, and still serves what it served before: why.
    Failed(String),
    /// The running process speaks no protocol version this program speaks, so it was not
    /// asked.
    Incompatible { ours: Vec<u32>, theirs: Vec<u32> },
    /// The running process could not be asked, or did not answer: why.
    Unreachable(String),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReloadError::Failed(reason) => write!(f, "reload failed, {reason}"),
            ReloadError::Incompatible { ours, theirs } => write!(
                f,
                "the running process speaks reload protocol version {}, this program {}",
                list(theirs),
                list(ours)
            ),
            ReloadError::Unreachable(reason) => f.write_str(reason),
        }
    }
}

/// The version to ask in: the highest one both ends speak.
fn choose(greeting: &str) -> Result<u32, ReloadError> {
    let greeting: Greeting = serde_json::from_str(greeting)
        .map_err(|e| ReloadError::Unreachable(format!("not a reload socket's greeting: {e}")))?;
    let common = VERSIONS.iter().filter(|v| greeting.versions.contains(v));
    common.max().copied().ok_or(ReloadError::Incompatible {
        ours: VERSIONS.to_vec(),
        theirs: greeting.versions,
    })
}

/// What a client makes of the server's answer: the status of a reload that is done, or why it
/// is not.
fn outcome(reply: Reply) -> Result<String, ReloadError> {
    match reply {
        Reply::Done { status } => Ok(status),
        Reply::Failed { reason } => Err(ReloadError::Failed(reason)),
        Reply::Refused { reason } => Err(ReloadError::Unreachable(format!(
            "the running process refused the request: {reason}"
        ))),
    }
}

/// Asks the process that listens at `socket` to reload and waits for the outcome, at most
/// `patience`. `Ok` is the status of the process that serves once the reload is done.
pub(crate) fn ask(socket: &Path, patience: Duration) -> Result<String, ReloadError> {
    let deadline = Instant::now() + patience;
    let unreachable = |why: String| ReloadError::Unreachable(why);
    let gone = |before: &str| {
        unreachable(format!(
            "the process at {} closed the connection before {before}; if it handed over \
             meanwhile, ask again",
            socket.display()
        ))
    };
    let failed = |e: io::Error, before: &str| match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => unreachable(format!(
            "no answer from the process at {} in {} s",
            socket.display(),
            patience.as_secs()
        )),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset => gone(before),
        _ => unreachable(format!("{}: {e}", socket.display())),
    };
    let stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            unreachable(format!("no process listens at {}: {e}", socket.display()))
        }
        _ => unreachable(format!("{}: {e}", socket.display())),
    })?;
    let mut reader = io::BufReader::new(&stream);
    let mut read = |before: &str| -> Result<String, ReloadError> {
        let left = deadline.saturating_duration_since(Instant::now());
        // A zero timeout would mean none. Some systems refuse to set one on a connection the
        // other end closed, whose reads do not wait anyway.
        let _ = stream.set_read_timeout(Some(left.max(Duration::from_millis(1))));
        let mut text = String::new();
        let line = (&mut reader).take(1 << 16).read_line(&mut text);
        match line.map_err(|e| failed(e, before))? {
            0 => Err(gone(before)),
            _ => Ok(text),
        }
    };
    let version = choose(&read("it greeted")?)?;
    let request = Request {
        version,
        request: RELOAD.to_owned(),
    };
    (&stream)
        .write_all(&line(&request))
        .map_err(|e| failed(e, "it answered"))?;
    let reply: Reply = serde_json::from_str(&read("it answered")?)
        .map_err(|e| unreachable(format!("not an answer: {e}")))?;
    outcome(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn wire<T: Serialize>(message: &T) -> Value {
        let line = line(message);
        assert_eq!(
            line.iter().filter(|&&byte| byte == b'\n').count(),
            1,
            "one line"
        );
        assert_eq!(line.last(), Some(&b'\n'));
        serde_json::from_slice(&line).unwrap()
    }

    #[test]
    fn each_message_has_its_documented_wire_form() {
        assert_eq!(
            wire(&Greeting { versions: vec![1] }),
            json!({ "versions": [1] })
        );
        let request = Request {
            version: 1,
            request: "reload".into(),
        };
        assert_eq!(wire(&request), json!({ "version": 1, "request": "reload" }));
        let done = Reply::Done {
            status: "serving generation 7".into(),
        };
        assert_eq!(
            wire(&done),
            json!({ "result": "done", "status": "serving generation 7" })
        );
        let failed = Reply::Failed {
            reason: "still serving generation 6: /sites/0: broken".into(),
        };
        assert_eq!(
            wire(&failed),
            json!({ "result": "failed", "reason": "still serving generation 6: /sites/0: broken" })
        );
        let refused = Reply::Refused {
            reason: "unknown request \"stop\"".into(),
        };
        assert_eq!(
            wire(&refused),
            json!({ "result": "refused", "reason": "unknown request \"stop\"" })
        );
    }

    #[test]
    fn a_reason_with_a_line_break_stays_one_line() {
        let failed = Reply::Failed {
            reason: "first\nsecond".into(),
        };
        assert_eq!(
            wire(&failed),
            json!({ "result": "failed", "reason": "first\nsecond" })
        );
    }

    #[test]
    fn a_request_is_admitted_in_a_version_this_build_speaks_and_for_a_reload_only() {
        assert_eq!(admit(br#"{"version":1,"request":"reload"}"#), Ok(()));
        assert_eq!(
            admit(br#"{"version":1,"request":"reload","later":{"x":1}}"#),
            Ok(()),
            "a field this build does not know is ignored"
        );
        assert_eq!(
            admit(br#"{"version":2,"request":"reload"}"#),
            Err("version 2 is not one this process speaks (1)".to_owned())
        );
        assert_eq!(
            admit(br#"{"version":1,"request":"stop"}"#),
            Err("unknown request \"stop\"".to_owned())
        );
        for not_a_request in [&b"reload"[..], br#"{"request":"reload"}"#, b"", b"[1]"] {
            let refused = admit(not_a_request).unwrap_err();
            assert!(refused.starts_with("not a request: "), "{refused}");
        }
    }

    #[test]
    fn a_client_asks_in_the_highest_version_both_ends_speak() {
        assert_eq!(choose(r#"{"versions":[1]}"#), Ok(1));
        assert_eq!(choose(r#"{"versions":[3,1,2]}"#), Ok(1));
        assert_eq!(
            choose(r#"{"versions":[1,2],"later":true}"#),
            Ok(1),
            "a field this build does not know is ignored"
        );
        assert_eq!(
            choose(r#"{"versions":[2,3]}"#),
            Err(ReloadError::Incompatible {
                ours: vec![1],
                theirs: vec![2, 3],
            })
        );
        assert_eq!(
            ReloadError::Incompatible {
                ours: vec![1],
                theirs: vec![2, 3],
            }
            .to_string(),
            "the running process speaks reload protocol version 2, 3, this program 1"
        );
        for not_a_greeting in ["HTTP/1.1 400 Bad Request", r#"{"version":1}"#, ""] {
            let Err(ReloadError::Unreachable(why)) = choose(not_a_greeting) else {
                panic!("{not_a_greeting:?} is no greeting");
            };
            assert!(why.starts_with("not a reload socket's greeting: "), "{why}");
        }
    }

    #[test]
    fn a_reload_s_outcome_maps_to_an_answer_and_back() {
        let done = Ok("serving generation 2".to_owned());
        assert_eq!(
            Reply::of(&done),
            Reply::Done {
                status: "serving generation 2".into()
            }
        );
        assert_eq!(
            outcome(Reply::of(&done)),
            Ok("serving generation 2".to_owned())
        );

        let kept = Err("still serving generation 1: /sites/0: broken".to_owned());
        assert_eq!(
            Reply::of(&kept),
            Reply::Failed {
                reason: "still serving generation 1: /sites/0: broken".into()
            }
        );
        let failed = outcome(Reply::of(&kept)).unwrap_err();
        assert_eq!(
            failed,
            ReloadError::Failed("still serving generation 1: /sites/0: broken".into())
        );
        assert_eq!(
            failed.to_string(),
            "reload failed, still serving generation 1: /sites/0: broken"
        );

        let refused = outcome(Reply::Refused {
            reason: "unknown request \"stop\"".into(),
        });
        assert_eq!(
            refused,
            Err(ReloadError::Unreachable(
                "the running process refused the request: unknown request \"stop\"".into()
            )),
            "a refusal is not a reload that failed"
        );
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn socket_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reload");
        (dir, path)
    }

    fn open(path: &Path) -> io::Result<Listener> {
        Listener::open(Source::Bind(path.to_owned()))
    }

    const GREETING: &str = "{\"versions\":[1]}\n";

    /// A client's connection, with `request` written to it.
    fn connect(path: &Path, request: &str) -> UnixStream {
        let mut stream = UnixStream::connect(path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream
    }

    /// What the server sent on `stream` before it closed it. A server that closes a
    /// connection it has not read to the end resets it, which ends the read as well.
    fn rest(mut stream: UnixStream) -> String {
        let mut rest = String::new();
        let _ = stream.read_to_string(&mut rest);
        rest
    }

    #[test]
    fn a_client_is_answered_with_the_outcome_of_the_reload_it_asked_for() {
        let (_dir, path) = socket_path();
        let runtime = runtime();
        let mut listener = runtime.block_on(async { open(&path) }).unwrap();
        for outcome in [
            Ok("serving generation 2".to_owned()),
            Err("still serving generation 2: /sites/0: broken".to_owned()),
        ] {
            let client = std::thread::spawn({
                let path = path.clone();
                move || ask(&path, Duration::from_secs(10))
            });
            runtime.block_on(async { listener.next().await.answer(&outcome).await });
            assert_eq!(client.join().unwrap(), outcome.map_err(ReloadError::Failed));
        }
    }

    #[test]
    fn a_request_that_is_not_a_reload_is_refused_and_the_next_client_served() {
        let (_dir, path) = socket_path();
        let runtime = runtime();
        let mut listener = runtime.block_on(async { open(&path) }).unwrap();
        let newer = connect(&path, "{\"version\":2,\"request\":\"reload\"}\n");
        let other = connect(&path, "{\"version\":1,\"request\":\"stop\"}\n");
        let long = connect(&path, &"x".repeat(2 * REQUEST_LIMIT));
        drop(connect(&path, ""));
        let asked = connect(&path, "{\"version\":1,\"request\":\"reload\"}\n");
        runtime.block_on(async {
            let asker = listener.next().await;
            asker.answer(&Ok("serving generation 2".into())).await;
        });
        let sent = |reply: &str| format!("{GREETING}{reply}\n");
        assert_eq!(
            rest(newer),
            sent(r#"{"result":"refused","reason":"version 2 is not one this process speaks (1)"}"#)
        );
        assert_eq!(
            rest(other),
            sent(r#"{"result":"refused","reason":"unknown request \"stop\""}"#)
        );
        assert!(
            !rest(long).contains("result"),
            "a line too long to be a request is not answered"
        );
        assert_eq!(
            rest(asked),
            sent(r#"{"result":"done","status":"serving generation 2"}"#)
        );
    }

    #[test]
    fn a_client_that_sends_no_request_is_dropped_when_its_time_is_up() {
        let (_dir, path) = socket_path();
        let runtime = runtime();
        let mut listener = runtime.block_on(async { open(&path) }).unwrap();
        listener.patience = Duration::from_millis(100);
        let silent = connect(&path, "");
        runtime.block_on(async {
            let waited = tokio::time::timeout(Duration::from_millis(500), listener.next());
            assert!(waited.await.is_err(), "nobody asked");
        });
        assert_eq!(rest(silent), GREETING, "greeted, and then closed");
    }

    #[test]
    fn a_request_that_arrives_in_pieces_survives_the_wait_being_dropped_between_them() {
        let (_dir, path) = socket_path();
        let runtime = runtime();
        let mut listener = runtime.block_on(async { open(&path) }).unwrap();
        let mut client = connect(&path, "{\"version\":1,");
        runtime.block_on(async {
            let dropped = tokio::time::timeout(Duration::from_millis(200), listener.next());
            assert!(dropped.await.is_err(), "half a request is no request");
        });
        client.write_all(b"\"request\":\"reload\"}\n").unwrap();
        runtime.block_on(async {
            let asker = listener.next().await;
            asker.answer(&Ok("serving generation 2".into())).await;
        });
        assert_eq!(
            rest(client),
            format!(
                "{GREETING}{}\n",
                r#"{"result":"done","status":"serving generation 2"}"#
            )
        );
    }

    #[test]
    fn a_socket_file_left_behind_is_replaced_and_a_served_one_is_not() {
        let (_dir, path) = socket_path();
        let runtime = runtime();
        let first = runtime.block_on(async { open(&path) }).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "for its owner alone");
        let Err(taken) = runtime.block_on(async { open(&path) }) else {
            panic!("two processes listen at one path");
        };
        assert_eq!(taken.to_string(), "another process listens there");

        drop(first);
        let mut second = runtime.block_on(async { open(&path) }).unwrap();
        let client = std::thread::spawn({
            let path = path.clone();
            move || ask(&path, Duration::from_secs(10))
        });
        runtime.block_on(async { second.next().await.answer(&Ok("up".into())).await });
        assert_eq!(client.join().unwrap(), Ok("up".to_owned()));

        let file = path.with_extension("txt");
        std::fs::write(&file, "kept").unwrap();
        let Err(not_a_socket) = runtime.block_on(async { open(&file) }) else {
            panic!("a file that is no socket was replaced");
        };
        assert_eq!(
            not_a_socket.to_string(),
            "a file that is not a socket is there"
        );
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "kept");
    }

    #[test]
    fn a_process_that_takes_over_answers_who_waits_in_the_socket_s_queue() {
        let (_dir, path) = socket_path();
        let runtime = runtime();
        let predecessor = runtime.block_on(async { open(&path) }).unwrap();
        let shared = predecessor.share().unwrap();
        let client = std::thread::spawn({
            let path = path.clone();
            move || ask(&path, Duration::from_secs(10))
        });
        // The client connected while the predecessor accepted nobody.
        std::thread::sleep(Duration::from_millis(100));
        drop(predecessor);
        let mut successor = runtime
            .block_on(async { Listener::open(Source::Inherited(shared)) })
            .unwrap();
        runtime.block_on(async {
            successor
                .next()
                .await
                .answer(&Ok("taken over".into()))
                .await
        });
        assert_eq!(client.join().unwrap(), Ok("taken over".to_owned()));
    }

    #[test]
    fn a_client_says_why_it_could_not_ask() {
        let (_dir, path) = socket_path();
        let Err(ReloadError::Unreachable(nothing)) = ask(&path, Duration::from_secs(1)) else {
            panic!("nothing is there to ask");
        };
        let expected = format!("no process listens at {}: ", path.display());
        assert!(nothing.starts_with(&expected), "{nothing}");

        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let silent = ask(&path, Duration::from_secs(1));
        assert_eq!(
            silent,
            Err(ReloadError::Unreachable(format!(
                "no answer from the process at {} in 1 s",
                path.display()
            )))
        );

        let server = std::thread::spawn(move || {
            let greet = |versions: &str| {
                let (mut stream, _) = listener.accept().unwrap();
                stream.write_all(versions.as_bytes()).unwrap();
                stream
            };
            // The connection the silent client left in the queue.
            drop(listener.accept().unwrap());
            drop(greet("{\"versions\":[2]}\n"));
            let mut asked = greet("{\"versions\":[1,2]}\n");
            let mut request = [0u8; 33];
            asked.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"{\"version\":1,\"request\":\"reload\"}\n");
        });
        assert_eq!(
            ask(&path, Duration::from_secs(10)),
            Err(ReloadError::Incompatible {
                ours: vec![1],
                theirs: vec![2],
            })
        );
        let Err(ReloadError::Unreachable(closed)) = ask(&path, Duration::from_secs(10)) else {
            panic!("the server went away without an answer");
        };
        assert!(
            closed.contains("closed the connection before it answered"),
            "{closed}"
        );
        server.join().unwrap();
    }
}
