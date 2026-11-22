//! Replacing the running binary without closing a listening socket.
//!
//! On SIGHUP the control thread compares the file at the path it was started from with the
//! file it runs ([`Launch::replaced`]). The same file: a config reload. Another file: a
//! handover to it, the two processes called predecessor and successor here.
//!
//! 1. The predecessor starts the file with its own arguments, as a child of its own parent
//!    (the service manager), and hands it a descriptor of every listening socket of every
//!    core, its session ticket keys, and two pipes. The [`Document`] that says which
//!    descriptor is what travels on a third pipe, whose number is in [`ENV`].
//! 2. The successor loads the config and starts its cores with every listener held: it accepts
//!    nothing and binds nothing. It then writes `ready` to the first pipe. A successor that
//!    cannot start writes `failed <reason>`, or just exits.
//! 3. On `ready` the predecessor tells the service manager that the successor is the main
//!    process, writes one byte to the second pipe, and drains. On anything else (a failure, an
//!    exit, [`READY_TIMEOUT`]) it kills the successor and keeps serving: no connection ever
//!    reached the successor. It also keeps serving when the byte cannot be written, which is
//!    a successor that went away after it reported.
//! 4. On that byte the successor serves the TCP listeners: the same sockets, so a connection
//!    that arrived in between waited in their queues. The QUIC listeners stay held until the
//!    second pipe closes, which the predecessor's cores do once they read no UDP socket any
//!    more: their QUIC connections are gone. A predecessor that dies closes it as well.
//!
//! The document is read by another version of this program. A field may be added and is
//! ignored by a version that does not know it; a change an older version must not ignore
//! raises [`VERSION`], and a successor refuses a version it does not know, which fails the
//! handover and leaves the predecessor serving.

use crate::net::listen::{Inherited, SocketKind};
use crate::tls::{TicketKey, TicketKeys};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

/// The environment variable that names the descriptor a successor reads its [`Document`]
/// from.
pub(crate) const ENV: &str = "UPSTREAMER_HANDOVER";

const VERSION: u32 = 1;

/// How long a successor has to report that it is ready. systemd gives a reload
/// `TimeoutStartSec` (90 s by default) before it calls it failed.
pub(crate) const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a successor waits to be made the main process after it reported ready.
const PROMOTION_TIMEOUT: Duration = Duration::from_secs(30);

/// The byte that makes a successor the main process.
const PROMOTED: u8 = b'M';

/// What a predecessor tells its successor: the descriptors the successor inherited, by
/// number, and the state worth carrying over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Document {
    version: u32,
    /// The pipe the successor reports on: one line, `ready` or `failed <reason>`.
    ready: RawFd,
    /// The pipe the predecessor answers on: [`PROMOTED`], then its end.
    control: RawFd,
    listeners: Vec<Sockets>,
    #[serde(default)]
    tickets: Option<Tickets>,
}

/// The sockets of one address, one per core of the predecessor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Sockets {
    transport: SocketKind,
    addr: SocketAddr,
    fds: Vec<RawFd>,
}

/// Session ticket keys, so a session resumes on the successor.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Tickets {
    lifetime_secs: u32,
    /// Since the current key became current: the successor rotates on the same schedule.
    age_secs: u64,
    current: Key,
    #[serde(default)]
    previous: Option<Key>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Key {
    /// 4 bytes, hexadecimal.
    id: String,
    /// 32 bytes, hexadecimal.
    secret: String,
}

impl std::fmt::Debug for Tickets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tickets")
            .field("age_secs", &self.age_secs)
            .finish_non_exhaustive()
    }
}

impl Tickets {
    pub fn of(keys: &TicketKeys, age: Duration) -> Tickets {
        let key = |key: &TicketKey| Key {
            id: hex(&key.id),
            secret: hex(key.secret()),
        };
        Tickets {
            lifetime_secs: keys.lifetime_secs,
            age_secs: age.as_secs(),
            current: key(&keys.current),
            previous: keys.previous.as_ref().map(key),
        }
    }

    /// The keys, and how long the current one has been current.
    fn keys(&self) -> Result<(TicketKeys, Duration), String> {
        let key = |key: &Key| -> Result<TicketKey, String> {
            let id = unhex(&key.id).ok_or("a ticket key id is not 4 hexadecimal bytes")?;
            let secret = unhex(&key.secret).ok_or("a ticket key is not 32 hexadecimal bytes")?;
            Ok(TicketKey::new(id, secret))
        };
        let keys = TicketKeys {
            current: key(&self.current)?,
            previous: self.previous.as_ref().map(key).transpose()?,
            lifetime_secs: self.lifetime_secs,
        };
        Ok((keys, Duration::from_secs(self.age_secs)))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.as_bytes();
    if text.len() != 2 * N || !text.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(text.chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

impl Document {
    /// Describes `sockets` (each core's, in core order) and the two pipe ends by their
    /// descriptor numbers, which are the same in a process forked from this one.
    fn describe(
        ready: RawFd,
        control: RawFd,
        sockets: &[Inherited],
        tickets: Option<Tickets>,
    ) -> Document {
        let mut listeners: Vec<Sockets> = Vec::new();
        for socket in sockets {
            let fd = socket.fd.as_raw_fd();
            match listeners
                .iter_mut()
                .find(|l| (l.transport, l.addr) == (socket.transport, socket.addr))
            {
                Some(listener) => listener.fds.push(fd),
                None => listeners.push(Sockets {
                    transport: socket.transport,
                    addr: socket.addr,
                    fds: vec![fd],
                }),
            }
        }
        Document {
            version: VERSION,
            ready,
            control,
            listeners,
            tickets,
        }
    }

    /// Reads a document: a version this build knows, and descriptor numbers that can be an
    /// inherited descriptor each, none of them twice.
    fn parse(text: &str) -> Result<Document, String> {
        #[derive(Deserialize)]
        struct Versioned {
            version: u32,
        }
        let versioned: Versioned =
            serde_json::from_str(text).map_err(|e| format!("not a handover document: {e}"))?;
        if versioned.version != VERSION {
            return Err(format!(
                "handover version {} is not the version {VERSION} this build speaks",
                versioned.version
            ));
        }
        let document: Document =
            serde_json::from_str(text).map_err(|e| format!("not a handover document: {e}"))?;
        let mut seen = Vec::new();
        for fd in document.fds() {
            if fd <= libc::STDERR_FILENO {
                return Err(format!("descriptor {fd} cannot be an inherited one"));
            }
            if seen.contains(&fd) {
                return Err(format!("descriptor {fd} is named twice"));
            }
            seen.push(fd);
        }
        if let Some(tickets) = &document.tickets {
            tickets.keys()?;
        }
        Ok(document)
    }

    /// Every descriptor the document names.
    fn fds(&self) -> impl Iterator<Item = RawFd> {
        let sockets = self.listeners.iter().flat_map(|l| l.fds.iter().copied());
        [self.ready, self.control].into_iter().chain(sockets)
    }

    /// Takes the descriptors the document names: each must be open, and each socket must be
    /// what the document says it is.
    ///
    /// # Safety
    ///
    /// Nothing else in this process owns a descriptor the document names: it describes the
    /// descriptors this process inherited, and is claimed once.
    unsafe fn claim(self) -> Result<Start, String> {
        if let Some(closed) = self.fds().find(|&fd| !is_open(fd)) {
            // Nothing is owned yet, so nothing of the document is closed on this path.
            return Err(format!("descriptor {closed} is not open"));
        }
        // SAFETY: open, distinct (`parse`), and nothing else owns them (the caller).
        let own = |fd: RawFd| unsafe { OwnedFd::from_raw_fd(fd) };
        let (ready, control) = (own(self.ready), own(self.control));
        // Owned before any is checked, so an error closes them all.
        let owned: Vec<(SocketKind, SocketAddr, OwnedFd)> = self
            .listeners
            .iter()
            .flat_map(|l| l.fds.iter().map(|&fd| (l.transport, l.addr, own(fd))))
            .collect();
        let mut sockets = Vec::with_capacity(owned.len());
        for (transport, addr, fd) in owned {
            let number = fd.as_raw_fd();
            let socket = Inherited::identify(fd)
                .map_err(|e| format!("descriptor {number} for {transport:?} {addr}: {e}"))?;
            if (socket.transport, socket.addr) != (transport, addr) {
                return Err(format!(
                    "descriptor {number} is {:?} {}, not {transport:?} {addr}",
                    socket.transport, socket.addr
                ));
            }
            sockets.push(socket);
        }
        for fd in [&ready, &control] {
            set_cloexec(fd.as_raw_fd()).map_err(|e| format!("a handover pipe: {e}"))?;
        }
        let tickets = self.tickets.as_ref().map(Tickets::keys).transpose()?;
        Ok(Start {
            launch: None,
            sockets,
            tickets,
            predecessor: Some(Predecessor {
                ready: Some(ready),
                control: Some(control),
                pipe: None,
            }),
        })
    }
}

fn is_open(fd: RawFd) -> bool {
    // SAFETY: F_GETFD reads the descriptor's flags and fails on a closed one.
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: sets a flag of a descriptor; fails on a closed one.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a process starts with besides its config.
#[derive(Default)]
pub(crate) struct Start {
    /// How to start this program again, where a running binary can be replaced.
    pub launch: Option<Launch>,
    /// Listening sockets to serve instead of binding new ones.
    pub sockets: Vec<Inherited>,
    /// Session ticket keys to start with, and the age of the current one.
    pub tickets: Option<(TicketKeys, Duration)>,
    /// The process this one takes over from.
    pub predecessor: Option<Predecessor>,
}

impl Start {
    /// What this process was started with: as a successor when [`ENV`] says so, else with the
    /// sockets the service manager kept for it, if any.
    pub fn from_env() -> Result<Start, String> {
        let var = |name: &str| std::env::var(name).ok();
        let mut start = match var(ENV) {
            // SAFETY: the variable is set by the predecessor that started this process, for
            // the descriptors it left open in it, and this runs once, before anything else
            // opens a descriptor.
            Some(fd) => unsafe { Start::inherit(&fd) }.map_err(|e| format!("{ENV}: {e}"))?,
            None => {
                let passed = passed_fds(
                    var("LISTEN_PID").as_deref(),
                    var("LISTEN_FDS").as_deref(),
                    std::process::id(),
                );
                Start {
                    // SAFETY: the service manager passed these descriptors to this process,
                    // and this runs once, before anything else opens a descriptor.
                    sockets: unsafe { stored(passed) },
                    ..Start::default()
                }
            }
        };
        start.launch = Launch::capture();
        Ok(start)
    }

    /// Reads the document from the descriptor numbered `fd` and claims what it names.
    ///
    /// # Safety
    ///
    /// As [`Document::claim`], for `fd` as well.
    unsafe fn inherit(fd: &str) -> Result<Start, String> {
        let fd: RawFd = fd
            .parse()
            .ok()
            .filter(|&fd| fd > libc::STDERR_FILENO && is_open(fd))
            .ok_or_else(|| format!("{fd:?} is not an open descriptor"))?;
        // SAFETY: open, and this process's alone (the caller).
        let mut pipe = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut text = String::new();
        io::Read::read_to_string(&mut pipe, &mut text).map_err(|e| e.to_string())?;
        let document = Document::parse(&text)?;
        if document.fds().any(|named| named == fd) {
            return Err(format!("descriptor {fd} is named twice"));
        }
        drop(pipe);
        // SAFETY: the caller's.
        unsafe { document.claim() }
    }
}

/// The descriptors the service manager passed to the process `own_pid`, from the two variables
/// of its protocol (`sd_listen_fds`): `LISTEN_FDS` descriptors from number 3 on, meant for the
/// process `LISTEN_PID` alone, which a child that inherited the environment is not.
fn passed_fds(pid: Option<&str>, count: Option<&str>, own_pid: u32) -> std::ops::Range<RawFd> {
    const FIRST: RawFd = 3;
    let count = match (pid.map(str::parse::<u32>), count.map(str::parse::<RawFd>)) {
        (Some(Ok(pid)), Some(Ok(count))) if pid == own_pid && count > 0 => count,
        _ => 0,
    };
    FIRST..FIRST.saturating_add(count)
}

/// Takes the passed descriptors: those that are listening sockets become inherited ones, the
/// others are closed.
///
/// # Safety
///
/// Nothing else in this process owns a descriptor in `passed`.
unsafe fn stored(passed: impl IntoIterator<Item = RawFd>) -> Vec<Inherited> {
    let mut sockets = Vec::new();
    for fd in passed.into_iter().filter(|&fd| is_open(fd)) {
        // SAFETY: open, and this process's alone (the caller).
        match Inherited::identify(unsafe { OwnedFd::from_raw_fd(fd) }) {
            Ok(socket) => sockets.push(socket),
            Err(e) => crate::log::warning!("descriptor {fd} from the service manager: {e}"),
        }
    }
    sockets
}

/// A successor's end of the handover.
pub(crate) struct Predecessor {
    ready: Option<OwnedFd>,
    control: Option<OwnedFd>,
    pipe: Option<tokio::net::unix::pipe::Receiver>,
}

impl Predecessor {
    /// Reports that this process is ready to serve.
    pub fn ready(&mut self) -> io::Result<()> {
        self.report("ready\n")
    }

    /// Reports why this process cannot serve. Says nothing once `ready` was reported.
    pub fn failed(&mut self, reason: &str) {
        let _ = self.report(&format!("failed {}\n", reason.replace('\n', " ")));
    }

    fn report(&mut self, line: &str) -> io::Result<()> {
        match self.ready.take() {
            Some(fd) => io::Write::write_all(&mut std::fs::File::from(fd), line.as_bytes()),
            None => Ok(()),
        }
    }

    fn pipe(&mut self) -> io::Result<&mut tokio::net::unix::pipe::Receiver> {
        if let Some(fd) = self.control.take() {
            self.pipe = Some(tokio::net::unix::pipe::Receiver::from_owned_fd(fd)?);
        }
        self.pipe
            .as_mut()
            .ok_or_else(|| io::Error::other("the handover pipe is closed"))
    }

    /// Resolves once the predecessor made this process the main one. An error when it went
    /// away instead, or said nothing for [`PROMOTION_TIMEOUT`].
    pub async fn promoted(&mut self) -> io::Result<()> {
        use tokio::io::AsyncReadExt;
        let pipe = self.pipe()?;
        let mut byte = [0u8; 1];
        match tokio::time::timeout(PROMOTION_TIMEOUT, pipe.read(&mut byte)).await {
            Ok(Ok(1)) if byte[0] == PROMOTED => Ok(()),
            Ok(Ok(_)) => Err(io::Error::other(
                "the process this one takes over from went away",
            )),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::other(
                "the process this one takes over from never let go",
            )),
        }
    }

    /// Resolves once the predecessor reads the UDP sockets no more: it said so, or it is gone.
    pub async fn released(&mut self) {
        use tokio::io::AsyncReadExt;
        let Ok(pipe) = self.pipe() else { return };
        let mut rest = [0u8; 16];
        while matches!(pipe.read(&mut rest).await, Ok(n) if n > 0) {}
    }
}

/// Identity of a file: the device it is on and its inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    fn of(path: &std::path::Path) -> io::Result<FileId> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok(FileId {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
}

/// How this process was started, to start its replacement the same way.
#[derive(Debug, Clone)]
pub(crate) struct Launch {
    /// The path the program was started from, symbolic links unresolved: the name whose
    /// target changes when the program is replaced.
    path: std::path::PathBuf,
    args: Vec<std::ffi::OsString>,
    running: FileId,
}

impl Launch {
    /// `None` where a handover is not supported (anything but Linux), or when the running
    /// file cannot be told from another: SIGHUP then always reloads the config.
    pub fn capture() -> Option<Launch> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let mut args = std::env::args_os();
        let name = std::path::PathBuf::from(args.next()?);
        // A name without a slash was found through PATH; the kernel's name for the running
        // file then stands in, as it is before anything replaces the file.
        let path = if name.components().count() > 1 {
            std::path::absolute(&name).ok()?
        } else {
            std::env::current_exe().ok()?
        };
        let running = FileId::of(std::path::Path::new("/proc/self/exe"))
            .or_else(|_| FileId::of(&path))
            .ok()?;
        Some(Launch {
            path,
            args: args.collect(),
            running,
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Whether the file at the start path is another file than the one this process runs.
    /// A path that cannot be read (a replacement under way) counts as the same file.
    pub fn replaced(&self) -> bool {
        FileId::of(&self.path).is_ok_and(|now| now != self.running)
    }
}

pub(crate) use predecessor::{Successor, offer};

/// Without the system calls a handover takes, [`Launch::capture`] finds nothing to hand over
/// to and no offer is ever made.
#[cfg(not(target_os = "linux"))]
mod predecessor {
    use super::*;

    pub(crate) struct Successor {
        pub pid: libc::pid_t,
    }

    impl Successor {
        pub fn promote(self) -> io::Result<std::sync::Arc<OwnedFd>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    pub(crate) async fn offer(
        _launch: &Launch,
        _sockets: Vec<Inherited>,
        _tickets: Option<Tickets>,
        _patience: Duration,
    ) -> Result<Successor, String> {
        Err("not supported on this system".to_owned())
    }
}

#[cfg(target_os = "linux")]
mod predecessor {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::sync::Arc;
    use tokio::io::AsyncBufReadExt;

    /// A started successor. Killed when dropped, unless it was promoted.
    pub(crate) struct Successor {
        pub pid: libc::pid_t,
        /// A handle on the process that cannot come to mean another one, where the kernel
        /// has them.
        pidfd: Option<OwnedFd>,
        control: Option<OwnedFd>,
    }

    impl Successor {
        /// Tells the successor it is the main process. The returned descriptor is the
        /// handover pipe: the successor serves QUIC once every copy of it is closed. An error
        /// when the successor is gone: nothing reads the pipe.
        pub fn promote(mut self) -> io::Result<Arc<OwnedFd>> {
            let control = self.control.take().expect("promoted once");
            let mut pipe = std::fs::File::from(control);
            io::Write::write_all(&mut pipe, &[PROMOTED])?;
            Ok(Arc::new(pipe.into()))
        }

        fn kill(&self) {
            // SAFETY: signals a process this one started. Through the pidfd the signal cannot
            // reach another process; without one the pid is the successor's unless it exited
            // and the number was given out again since it started.
            unsafe {
                match &self.pidfd {
                    Some(pidfd) => {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            pidfd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        );
                    }
                    None => {
                        libc::kill(self.pid, libc::SIGKILL);
                    }
                }
            }
        }
    }

    impl Drop for Successor {
        fn drop(&mut self) {
            if self.control.is_some() {
                self.kill();
            }
        }
    }

    fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` has room for the two descriptors pipe2 returns, which nothing else
        // owns.
        unsafe {
            if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])))
        }
    }

    /// Starts the program at `launch` as a successor that inherits `sockets`, and waits until
    /// it is ready. An error says why it is not; the successor is dead by then.
    pub(crate) async fn offer(
        launch: &Launch,
        sockets: Vec<Inherited>,
        tickets: Option<Tickets>,
        patience: Duration,
    ) -> Result<Successor, String> {
        let (successor, ready) =
            start(launch, sockets, tickets).map_err(|e| format!("cannot start it: {e}"))?;
        let ready = tokio::net::unix::pipe::Receiver::from_owned_fd(ready)
            .map_err(|e| format!("the handover pipe: {e}"))?;
        let mut line = String::new();
        let mut ready = tokio::io::BufReader::new(ready);
        match tokio::time::timeout(patience, ready.read_line(&mut line)).await {
            Err(_) => Err(format!("not ready after {} s", patience.as_secs())),
            Ok(Err(e)) => Err(format!("the handover pipe: {e}")),
            Ok(Ok(_)) => match line.trim_end() {
                "ready" => Ok(successor),
                "" => Err("it exited before it was ready".to_owned()),
                other => Err(other.strip_prefix("failed ").unwrap_or(other).to_owned()),
            },
        }
    }

    /// Starts the successor; returns it and the pipe it reports on.
    fn start(
        launch: &Launch,
        sockets: Vec<Inherited>,
        tickets: Option<Tickets>,
    ) -> io::Result<(Successor, OwnedFd)> {
        let (document_r, document_w) = pipe()?;
        let (ready_r, ready_w) = pipe()?;
        let (control_r, control_w) = pipe()?;
        let (pid_r, pid_w) = pipe()?;
        let document = Document::describe(
            ready_w.as_raw_fd(),
            control_r.as_raw_fd(),
            &sockets,
            tickets,
        );
        write_document(document_w, &document)?;

        // The descriptors the successor keeps, at the numbers they have here.
        let keep: Vec<RawFd> = document.fds().chain([document_r.as_raw_fd()]).collect();
        let pid_w_fd = pid_w.as_raw_fd();
        let mut command = std::process::Command::new(&launch.path);
        command
            .args(&launch.args)
            .env(ENV, document_r.as_raw_fd().to_string())
            // The service manager's socket activation variables name this process.
            .env_remove("LISTEN_PID")
            .env_remove("LISTEN_FDS")
            .env_remove("LISTEN_FDNAMES");
        // SAFETY: the closure runs in the forked child, where it only calls fcntl, clone,
        // write and _exit, none of which allocates or takes a lock.
        unsafe {
            command.pre_exec(move || {
                for &fd in &keep {
                    if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                // The program runs in a child of this child, which exits at once: the
                // program's parent is then this process's parent, the service manager, which
                // supervises a main process fully only when it is its own child.
                match libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) {
                    -1 => Err(io::Error::last_os_error()),
                    0 => Ok(()),
                    pid => {
                        let pid = (pid as libc::pid_t).to_ne_bytes();
                        libc::write(pid_w_fd, pid.as_ptr().cast(), pid.len());
                        libc::_exit(0)
                    }
                }
            });
        }
        // Returns once the program runs (or could not be run), which is after the middle
        // process wrote the pid.
        let mut middle = command.spawn()?;
        let _ = middle.wait();
        drop((pid_w, document_r, ready_w, control_r, sockets));
        let mut pid = [0u8; size_of::<libc::pid_t>()];
        io::Read::read_exact(&mut std::fs::File::from(pid_r), &mut pid)?;
        let pid = libc::pid_t::from_ne_bytes(pid);
        // SAFETY: pidfd_open takes a pid and flags, and returns a new descriptor or -1.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        // SAFETY: a descriptor pidfd_open just returned, owned by nothing else.
        let pidfd = (pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) });
        let successor = Successor {
            pid,
            pidfd,
            control: Some(control_w),
        };
        Ok((successor, ready_r))
    }

    /// Writes the document into its pipe and closes the pipe, before anything reads it: the
    /// pipe is made as large as the document where the default does not hold it.
    fn write_document(pipe: OwnedFd, document: &Document) -> io::Result<()> {
        let text = serde_json::to_vec(document).map_err(io::Error::other)?;
        // SAFETY: both calls take the descriptor and an integer.
        unsafe {
            if libc::fcntl(pipe.as_raw_fd(), libc::F_GETPIPE_SZ) < text.len() as libc::c_int
                && libc::fcntl(
                    pipe.as_raw_fd(),
                    libc::F_SETPIPE_SZ,
                    text.len() as libc::c_int,
                ) == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        io::Write::write_all(&mut std::fs::File::from(pipe), &text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ListenerKind;
    use std::os::fd::IntoRawFd;

    use ListenerKind::{Http, Https, Quic};

    fn pipe() -> (OwnedFd, OwnedFd) {
        let (read, write) = std::io::pipe().unwrap();
        (read.into(), write.into())
    }

    /// A document for `sockets` and two fresh pipes, with the ends the predecessor keeps.
    fn described(
        sockets: &[Inherited],
        tickets: Option<Tickets>,
    ) -> (Document, OwnedFd, OwnedFd, OwnedFd, OwnedFd) {
        let (ready_r, ready_w) = pipe();
        let (control_r, control_w) = pipe();
        let document =
            Document::describe(ready_w.as_raw_fd(), control_r.as_raw_fd(), sockets, tickets);
        (document, ready_r, ready_w, control_r, control_w)
    }

    /// Gives up the descriptors a document names, as a process forked from the describing one
    /// holds them: by number only.
    fn hand_down(ready_w: OwnedFd, control_r: OwnedFd, sockets: Vec<Inherited>) {
        let _ = ready_w.into_raw_fd();
        let _ = control_r.into_raw_fd();
        for socket in sockets {
            let _ = socket.fd.into_raw_fd();
        }
    }

    #[test]
    fn a_document_lists_each_address_once_with_its_sockets_in_core_order() {
        let first = [
            Inherited::fresh(Http),
            Inherited::fresh(Https),
            Inherited::fresh(Quic),
        ];
        let second = [
            first[0].sibling(Http),
            first[1].sibling(Https),
            first[2].sibling(Quic),
        ];
        let sockets: Vec<Inherited> = first.into_iter().chain(second).collect();
        let (a, b, c) = (sockets[0].addr, sockets[1].addr, sockets[2].addr);
        let fd = |i: usize| sockets[i].fd.as_raw_fd();
        let (document, ..) = described(&sockets, None);
        assert_eq!(
            document.listeners,
            [
                Sockets {
                    transport: SocketKind::Tcp,
                    addr: a,
                    fds: vec![fd(0), fd(3)]
                },
                Sockets {
                    transport: SocketKind::Tcp,
                    addr: b,
                    fds: vec![fd(1), fd(4)]
                },
                Sockets {
                    transport: SocketKind::Udp,
                    addr: c,
                    fds: vec![fd(2), fd(5)]
                },
            ]
        );
        let text = serde_json::to_string(&document).unwrap();
        assert_eq!(Document::parse(&text).unwrap(), document);
    }

    #[test]
    fn the_wire_form_is_the_documented_one() {
        let addr: SocketAddr = "[::]:443".parse().unwrap();
        let document = Document {
            version: 1,
            ready: 7,
            control: 9,
            listeners: vec![Sockets {
                transport: SocketKind::Udp,
                addr,
                fds: vec![11, 12],
            }],
            tickets: Some(Tickets {
                lifetime_secs: 43_200,
                age_secs: 60,
                current: Key {
                    id: "01020304".into(),
                    secret: "ab".repeat(32),
                },
                previous: None,
            }),
        };
        let wire = serde_json::json!({
            "version": 1,
            "ready": 7,
            "control": 9,
            "listeners": [{ "transport": "udp", "addr": "[::]:443", "fds": [11, 12] }],
            "tickets": {
                "lifetimeSecs": 43_200,
                "ageSecs": 60,
                "current": { "id": "01020304", "secret": "ab".repeat(32) },
                "previous": null,
            },
        });
        assert_eq!(serde_json::to_value(&document).unwrap(), wire);
        assert_eq!(Document::parse(&wire.to_string()).unwrap(), document);
    }

    #[test]
    fn a_field_this_build_does_not_know_is_ignored_and_another_version_is_refused() {
        let known = serde_json::json!({
            "version": 1, "ready": 7, "control": 9, "listeners": [], "later": { "x": 1 },
        });
        let document = Document::parse(&known.to_string()).unwrap();
        assert_eq!((document.ready, document.control), (7, 9));
        assert_eq!(document.tickets, None);

        let newer = serde_json::json!({ "version": 2, "sockets": "elsewhere" });
        let refused = Document::parse(&newer.to_string()).unwrap_err();
        assert!(
            refused.contains("version 2") && refused.contains("version 1"),
            "{refused}"
        );
    }

    #[test]
    fn a_document_that_cannot_describe_inherited_descriptors_is_refused() {
        let with = |ready: i32, control: i32, fds: &[i32], tickets: serde_json::Value| {
            let text = serde_json::json!({
                "version": 1, "ready": ready, "control": control,
                "listeners": [{ "transport": "tcp", "addr": "127.0.0.1:80", "fds": fds }],
                "tickets": tickets,
            });
            Document::parse(&text.to_string())
        };
        let none = serde_json::Value::Null;
        assert!(with(7, 9, &[10, 11], none.clone()).is_ok());
        let twice = with(7, 9, &[10, 7], none.clone()).unwrap_err();
        assert!(twice.contains("descriptor 7 is named twice"), "{twice}");
        let same = with(7, 7, &[], none.clone()).unwrap_err();
        assert!(same.contains("named twice"), "{same}");
        let stdio = with(7, 9, &[2], none.clone()).unwrap_err();
        assert!(stdio.contains("descriptor 2 cannot"), "{stdio}");
        let negative = with(-1, 9, &[], none.clone()).unwrap_err();
        assert!(negative.contains("descriptor -1 cannot"), "{negative}");

        let key = |id: &str, secret: &str| {
            serde_json::json!({
                "lifetimeSecs": 60, "ageSecs": 0, "current": { "id": id, "secret": secret },
            })
        };
        assert!(with(7, 9, &[], key("0a0b0c0d", &"00".repeat(32))).is_ok());
        let short = with(7, 9, &[], key("0a0b0c0d", "00")).unwrap_err();
        assert!(short.contains("not 32 hexadecimal bytes"), "{short}");
        let id = with(7, 9, &[], key("xyzw0000", &"00".repeat(32))).unwrap_err();
        assert!(id.contains("not 4 hexadecimal bytes"), "{id}");

        let garbage = Document::parse("ready").unwrap_err();
        assert!(garbage.starts_with("not a handover document"), "{garbage}");
    }

    #[test]
    fn descriptors_are_passed_to_the_process_the_service_manager_named() {
        assert_eq!(passed_fds(Some("41"), Some("3"), 41), 3..6);
        assert_eq!(
            passed_fds(Some("40"), Some("3"), 41),
            3..3,
            "meant for another process: this one inherited the variables"
        );
        assert_eq!(passed_fds(None, Some("3"), 41), 3..3);
        assert_eq!(passed_fds(Some("41"), None, 41), 3..3);
        assert_eq!(passed_fds(Some("41"), Some("0"), 41), 3..3);
        assert_eq!(passed_fds(Some("41"), Some("-2"), 41), 3..3);
        assert_eq!(passed_fds(Some("41"), Some("many"), 41), 3..3);
    }

    #[test]
    fn passed_descriptors_that_are_listening_sockets_are_inherited() {
        let tcp = Inherited::fresh(Http);
        let addr = tcp.addr;
        let (read, write) = pipe();
        // A socket, a pipe and a number that is no descriptor, as if passed by the service
        // manager.
        let passed = [tcp.fd.into_raw_fd(), read.into_raw_fd(), RawFd::MAX];
        // SAFETY: the test gave up the two descriptors, and the third is not one.
        let sockets = unsafe { stored(passed) };
        assert_eq!(sockets.len(), 1, "the pipe is not a socket");
        assert_eq!(
            (
                sockets[0].transport,
                sockets[0].addr,
                sockets[0].fd.as_raw_fd()
            ),
            (SocketKind::Tcp, addr, passed[0])
        );
        let closed = io::Write::write_all(&mut std::fs::File::from(write), b"x").unwrap_err();
        assert_eq!(
            closed.kind(),
            io::ErrorKind::BrokenPipe,
            "what is not a socket is closed"
        );
    }

    #[test]
    fn ticket_keys_survive_the_document() {
        use rustls::server::ProducesTickets;
        let keys = TicketKeys::generate(600).rotated();
        let ticket = keys.encrypt(b"session").unwrap();
        let old = TicketKeys {
            current: TicketKey::new(
                keys.previous.as_ref().unwrap().id,
                *keys.previous.as_ref().unwrap().secret(),
            ),
            previous: None,
            lifetime_secs: 600,
        }
        .encrypt(b"older session")
        .unwrap();

        let tickets = Tickets::of(&keys, Duration::from_secs(90));
        let text = serde_json::to_string(&tickets).unwrap();
        let (carried, age) = serde_json::from_str::<Tickets>(&text)
            .unwrap()
            .keys()
            .unwrap();
        assert_eq!(age, Duration::from_secs(90));
        assert_eq!(carried.lifetime_secs, 600);
        assert_eq!(carried.decrypt(&ticket).as_deref(), Some(&b"session"[..]));
        assert_eq!(
            carried.decrypt(&old).as_deref(),
            Some(&b"older session"[..]),
            "the previous key decrypts too"
        );
        assert!(
            !format!("{tickets:?}").contains(&tickets.current.secret),
            "a key is not printed"
        );
    }

    #[test]
    fn claiming_a_document_yields_the_sockets_it_describes() {
        let (tcp, udp) = (Inherited::fresh(Http), Inherited::fresh(Quic));
        let (a, b) = (tcp.addr, udp.addr);
        let other_core = tcp.sibling(Http);
        let sockets = vec![tcp, udp, other_core];
        let numbers: Vec<RawFd> = sockets.iter().map(|s| s.fd.as_raw_fd()).collect();
        let keys = TicketKeys::generate(600);
        let tickets = Tickets::of(&keys, Duration::from_secs(5));
        let (document, _ready_r, ready_w, control_r, _control_w) =
            described(&sockets, Some(tickets));
        hand_down(ready_w, control_r, sockets);

        // SAFETY: `hand_down` gave up every descriptor the document names.
        let start = unsafe { document.claim() }.unwrap();
        let claimed: Vec<_> = start
            .sockets
            .iter()
            .map(|s| (s.transport, s.addr, s.fd.as_raw_fd()))
            .collect();
        assert_eq!(
            claimed,
            [
                (SocketKind::Tcp, a, numbers[0]),
                (SocketKind::Tcp, a, numbers[2]),
                (SocketKind::Udp, b, numbers[1]),
            ],
            "grouped by address, each address's sockets in core order"
        );
        let (carried, age) = start.tickets.unwrap();
        assert_eq!(carried.current.id, keys.current.id);
        assert_eq!(age, Duration::from_secs(5));
        assert!(start.predecessor.is_some());
    }

    #[test]
    fn a_socket_that_is_not_what_the_document_says_fails_the_claim() {
        let sockets = vec![Inherited::fresh(Http)];
        let a = sockets[0].addr;
        let b = SocketAddr::new(a.ip(), a.port().wrapping_add(1));
        let (mut document, _ready_r, ready_w, control_r, _control_w) = described(&sockets, None);
        document.listeners[0].addr = b;
        hand_down(ready_w, control_r, sockets);
        // SAFETY: `hand_down` gave up every descriptor the document names.
        let moved = unsafe { document.claim() }.err().unwrap();
        assert!(
            moved.contains(&format!("is Tcp {a}, not Tcp {b}")),
            "{moved}"
        );

        let sockets = vec![Inherited::fresh(Quic)];
        let a = sockets[0].addr;
        let (mut document, _ready_r, ready_w, control_r, _control_w) = described(&sockets, None);
        document.listeners[0].transport = SocketKind::Tcp;
        hand_down(ready_w, control_r, sockets);
        // SAFETY: as above.
        let datagram = unsafe { document.claim() }.err().unwrap();
        assert!(
            datagram.contains(&format!("is Udp {a}, not Tcp {a}")),
            "{datagram}"
        );

        let (file_r, _file_w) = pipe();
        let (mut document, _ready_r, ready_w, control_r, _control_w) = described(&[], None);
        document.listeners.push(Sockets {
            transport: SocketKind::Tcp,
            addr: a,
            fds: vec![file_r.as_raw_fd()],
        });
        let _ = file_r.into_raw_fd();
        hand_down(ready_w, control_r, Vec::new());
        // SAFETY: as above, the pipe that stands in for a socket included.
        let not_a_socket = unsafe { document.claim() }.err().unwrap();
        assert!(
            not_a_socket.contains(&format!("for Tcp {a}")),
            "{not_a_socket}"
        );
    }

    #[test]
    fn a_descriptor_that_is_not_open_fails_the_claim_and_leaves_the_others_alone() {
        let sockets = vec![Inherited::fresh(Http)];
        let (mut document, _ready_r, ready_w, _control_r, _control_w) = described(&sockets, None);
        // No process has this many descriptors, so the number is never an open one.
        document.control = RawFd::MAX;
        // SAFETY: nothing is taken when a descriptor is not open; the test keeps its own.
        let error = unsafe { document.claim() }.err().unwrap();
        assert_eq!(error, format!("descriptor {} is not open", RawFd::MAX));
        assert!(
            is_open(ready_w.as_raw_fd()) && is_open(sockets[0].fd.as_raw_fd()),
            "a refused document closes nothing"
        );
    }

    #[test]
    fn a_successor_reports_once_and_follows_the_predecessor() {
        let (document, ready_r, ready_w, control_r, control_w) = described(&[], None);
        hand_down(ready_w, control_r, Vec::new());
        // SAFETY: `hand_down` gave up every descriptor the document names.
        let mut predecessor = unsafe { document.claim() }.unwrap().predecessor.unwrap();
        predecessor.ready().unwrap();
        predecessor.failed("too late to matter");
        let mut said = String::new();
        io::Read::read_to_string(&mut std::fs::File::from(ready_r), &mut said).unwrap();
        assert_eq!(said, "ready\n");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut control = std::fs::File::from(control_w);
            let waiting = tokio::time::timeout(Duration::from_millis(50), predecessor.promoted());
            assert!(waiting.await.is_err(), "not promoted before the byte");
            io::Write::write_all(&mut control, &[PROMOTED]).unwrap();
            predecessor.promoted().await.unwrap();
            let held = tokio::time::timeout(Duration::from_millis(50), predecessor.released());
            assert!(held.await.is_err(), "held while the pipe is open");
            drop(control);
            predecessor.released().await;
        });
    }

    #[test]
    fn a_successor_reports_its_failure_and_gives_up_when_the_predecessor_is_gone() {
        let (document, ready_r, ready_w, control_r, control_w) = described(&[], None);
        hand_down(ready_w, control_r, Vec::new());
        // SAFETY: `hand_down` gave up every descriptor the document names.
        let mut predecessor = unsafe { document.claim() }.unwrap().predecessor.unwrap();
        predecessor.failed("/sites/0: broken\nand more");
        let mut said = String::new();
        io::Read::read_to_string(&mut std::fs::File::from(ready_r), &mut said).unwrap();
        assert_eq!(said, "failed /sites/0: broken and more\n");

        drop(control_w);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let gone = runtime.block_on(predecessor.promoted()).unwrap_err();
        assert!(gone.to_string().contains("went away"), "{gone}");
    }

    #[cfg(target_os = "linux")]
    mod offers {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// A launch of `/bin/sh -c script`: the script stands in for a successor.
        fn shell(script: &str) -> Launch {
            let path = std::path::PathBuf::from("/bin/sh");
            Launch {
                running: FileId::of(&path).unwrap(),
                path,
                args: vec!["-c".into(), script.into()],
            }
        }

        /// Reads the document and binds its `ready` descriptor number to `$ready`. Descriptors
        /// are reached through `/proc/self/fd`: not every `sh` redirects to a number above 9.
        const READ: &str = r#"doc=$(cat "/proc/self/fd/$UPSTREAMER_HANDOVER")
            ready=$(printf %s "$doc" | sed 's/.*"ready":\([0-9]*\).*/\1/')"#;

        fn offered(script: &str, patience: Duration) -> Result<Successor, String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(offer(&shell(script), Vec::new(), None, patience))
        }

        /// Whether `pid` still runs (a process that exited and awaits its parent does not).
        fn runs(pid: libc::pid_t) -> bool {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .is_ok_and(|stat| !stat.rsplit(')').next().unwrap_or("").starts_with(" Z"))
        }

        fn eventually(what: &str, condition: impl Fn() -> bool) {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !condition() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "never happened: {what}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        #[test]
        fn a_successor_that_reports_ready_is_promoted_and_outlives_the_offer() {
            let dir = tempfile::tempdir().unwrap();
            let seen = dir.path().join("seen");
            let script = format!(
                r#"{READ}
                control=$(printf %s "$doc" | sed 's/.*"control":\([0-9]*\).*/\1/')
                echo ready > "/proc/self/fd/$ready"
                head -c 1 "/proc/self/fd/$control" > {seen}.part
                echo " $(cut -d' ' -f4 /proc/$$/stat)" >> {seen}.part
                mv {seen}.part {seen}
                cat "/proc/self/fd/$control" > /dev/null
                echo released > {seen}.released"#,
                seen = seen.display()
            );
            let successor = offered(&script, Duration::from_secs(10)).unwrap();
            let pid = successor.pid;
            assert!(runs(pid), "the successor waits to be promoted");
            let pipe = successor.promote().unwrap();
            eventually("the successor read the promotion", || seen.exists());
            let said = std::fs::read_to_string(&seen).unwrap();
            let (byte, parent) = said.trim().split_once(' ').unwrap();
            assert_eq!(byte, "M");
            assert_ne!(
                parent.parse::<u32>().unwrap(),
                std::process::id(),
                "the successor is not this process's child"
            );
            let released = dir.path().join("seen.released");
            std::thread::sleep(Duration::from_millis(50));
            assert!(!released.exists(), "held while a copy of the pipe is open");
            drop(pipe);
            eventually("the pipe's end reached the successor", || released.exists());
        }

        #[test]
        fn a_successor_that_went_away_after_it_reported_ready_cannot_be_promoted() {
            let script = format!(r#"{READ}; echo ready > "/proc/self/fd/$ready""#);
            let successor = offered(&script, Duration::from_secs(10)).unwrap();
            let pid = successor.pid;
            eventually("the successor exited", || !runs(pid));
            let gone = successor.promote().expect_err("nothing reads the pipe");
            assert_eq!(gone.kind(), io::ErrorKind::BrokenPipe, "{gone}");
        }

        #[test]
        fn a_successor_that_exits_before_it_is_ready_fails_the_offer() {
            let error = offered("exit 3", Duration::from_secs(10)).err().unwrap();
            assert_eq!(error, "it exited before it was ready");
        }

        #[test]
        fn a_successor_that_says_why_it_failed_fails_the_offer_with_its_reason() {
            let script =
                format!(r#"{READ}; echo 'failed /sites/0: broken' > "/proc/self/fd/$ready""#);
            let error = offered(&script, Duration::from_secs(10)).err().unwrap();
            assert_eq!(error, "/sites/0: broken");
        }

        #[test]
        fn a_successor_that_is_never_ready_is_killed_when_patience_runs_out() {
            let dir = tempfile::tempdir().unwrap();
            let pid_file = dir.path().join("pid");
            let script = format!("echo $$ > {}; exec sleep 600", pid_file.display());
            let started = std::time::Instant::now();
            let error = offered(&script, Duration::from_millis(300)).err().unwrap();
            assert_eq!(error, "not ready after 0 s");
            assert!(started.elapsed() < Duration::from_secs(5));
            let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            eventually("the successor is killed", || !runs(pid));
        }

        #[test]
        fn a_file_that_cannot_be_run_fails_the_offer() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("upstreamer");
            std::fs::write(&path, b"not a program").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let launch = Launch {
                running: FileId::of(&path).unwrap(),
                path,
                args: Vec::new(),
            };
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let offer = offer(&launch, Vec::new(), None, Duration::from_secs(10));
            let error = runtime.block_on(offer).err().unwrap();
            assert!(error.starts_with("cannot start it: "), "{error}");
        }

        #[test]
        fn another_file_at_the_start_path_is_a_replacement_and_a_missing_one_is_not() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("upstreamer");
            std::fs::write(&path, b"one").unwrap();
            let launch = Launch {
                running: FileId::of(&path).unwrap(),
                path: path.clone(),
                args: Vec::new(),
            };
            assert!(!launch.replaced(), "the file it runs");
            std::fs::write(&path, b"rewritten in place").unwrap();
            assert!(!launch.replaced(), "the same file with other content");

            let link = dir.path().join("current");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            let through_link = Launch {
                path: link.clone(),
                ..launch.clone()
            };
            assert!(!through_link.replaced(), "a link to the file it runs");

            let next = dir.path().join("next");
            std::fs::write(&next, b"two").unwrap();
            std::fs::remove_file(&link).unwrap();
            assert!(!through_link.replaced(), "no file at the path");
            std::os::unix::fs::symlink(&next, &link).unwrap();
            assert!(through_link.replaced(), "the link names another file");

            std::fs::rename(&next, &path).unwrap();
            assert!(launch.replaced(), "another file renamed over the path");
        }
    }
}
