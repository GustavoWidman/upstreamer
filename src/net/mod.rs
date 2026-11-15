//! Sockets and transports. Our own socket type over `AsyncFd` instead of tokio's `TcpStream`,
//! for two reasons the hot path depends on:
//! - readiness is cleared by us after a short read or write (the edge-triggered rule nginx
//!   uses), so the read after a drained socket waits on epoll instead of costing an EAGAIN
//!   syscall;
//! - the raw fd is reachable for sendfile, splice and kTLS setsockopt, and an io_uring
//!   backend can replace the internals behind the same methods.

pub(crate) mod buf;
pub(crate) mod listen;

use crate::tls::record::{MAX_RECORD, Opened, Session, record_len};
use buf::BufPool;
use bytes::{Buf, BytesMut};
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Spare capacity [`Socket::read`] guarantees before reading.
const MIN_SPARE: usize = 4096;

/// A nonblocking TCP socket registered with the core's reactor (edge-triggered).
pub(crate) struct Socket {
    fd: AsyncFd<OwnedFd>,
}

impl Socket {
    /// Registers an already nonblocking socket with the current core's reactor.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Socket> {
        Ok(Socket { fd: register(fd)? })
    }
    /// Nonblocking connect to an origin, TCP_NODELAY set; resolves when the connection is
    /// established (the caller bounds it with the dial timeout).
    pub async fn connect(addr: SocketAddr) -> io::Result<Socket> {
        use socket2::{Domain, Protocol, Type};
        let sock =
            socket2::Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
        sock.set_nonblocking(true)?;
        sock.set_tcp_nodelay(true)?;
        match sock.connect(&addr.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }
        let sock = Socket::from_fd(sock.into())?;
        // Writability (or an error/hang-up event) marks the end of the handshake; SO_ERROR
        // says which.
        let _ready = sock.fd.writable().await?;
        match socket2::SockRef::from(sock.fd.get_ref()).take_error()? {
            Some(e) => Err(e),
            None => Ok(sock),
        }
    }
    /// Reads into the spare capacity of `buf` (growing it to at least 4 KiB spare). `Ok(0)` is
    /// EOF. A read shorter than the spare capacity clears read readiness.
    pub async fn read(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        if buf.capacity() - buf.len() < MIN_SPARE {
            buf.reserve(MIN_SPARE);
        }
        loop {
            let mut guard = self.fd.readable().await?;
            let spare = buf.spare_capacity_mut();
            let want = spare.len();
            match sys_read(
                guard.get_inner().as_raw_fd(),
                spare.as_mut_ptr().cast(),
                want,
            ) {
                Ok(n) => {
                    // The socket is drained: the next wait is on epoll, not on an EAGAIN read.
                    // An edge that arrived meanwhile has a newer tick and survives the clear.
                    if n < want {
                        guard.clear_ready();
                    }
                    // SAFETY: the kernel initialised `n` bytes of the spare capacity.
                    unsafe { buf.set_len(buf.len() + n) };
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
    /// Writes all of `bufs` (writev), waiting on writability as needed.
    pub async fn write_all_vectored(&mut self, mut bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        IoSlice::advance_slices(&mut bufs, 0);
        while !bufs.is_empty() {
            let mut guard = self.fd.writable().await?;
            match sys_writev(guard.get_inner().as_raw_fd(), bufs) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    // A short write means the send buffer is full; the next attempt waits for
                    // the kernel to report space.
                    if n < total_len(bufs) {
                        guard.clear_ready();
                    }
                    IoSlice::advance_slices(&mut bufs, n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    /// Waits for readability without reading (idle keep-alive connections hold no buffer).
    pub async fn readable(&self) -> io::Result<()> {
        self.fd.readable().await.map(drop)
    }
    /// Readiness says the peer closed or sent bytes (pooled upstream liveness check): no
    /// syscall.
    pub fn hung_up_or_readable(&self) -> bool {
        let mut cx = Context::from_waker(Waker::noop());
        self.fd.poll_read_ready(&mut cx).is_ready()
    }
    /// Sends `len` bytes of `file` from `offset`. Returns the bytes sent, which is less than
    /// `len` only when the file ended first.
    pub async fn sendfile(
        &mut self,
        file: BorrowedFd<'_>,
        offset: u64,
        len: u64,
    ) -> io::Result<u64> {
        let mut sent = 0;
        while sent < len {
            let mut guard = self.fd.writable().await?;
            let chunk = (len - sent).min(1 << 30) as usize;
            match sys_sendfile(
                guard.get_inner().as_raw_fd(),
                file.as_raw_fd(),
                offset + sent,
                chunk,
            ) {
                Ok(0) => break,
                // A short count means either a full send buffer or the end of the file; the
                // next call tells them apart (EAGAIN or 0), so readiness is left alone.
                Ok(n) => sent += n as u64,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(sent)
    }
    /// One nonblocking write that never waits: for a last record (close_notify, an alert) to a
    /// peer that may have stopped reading.
    pub fn try_write(&self, buf: &[u8]) -> io::Result<usize> {
        sys_writev(self.fd.get_ref().as_raw_fd(), &[IoSlice::new(buf)])
    }
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.get_ref().as_fd()
    }
    fn poll_read_buf(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            // SAFETY: the kernel only writes into the slice; `assume_init` covers what it wrote.
            let unfilled = unsafe { buf.unfilled_mut() };
            let want = unfilled.len();
            match sys_read(
                guard.get_inner().as_raw_fd(),
                unfilled.as_mut_ptr().cast(),
                want,
            ) {
                Ok(n) => {
                    if n < want {
                        guard.clear_ready();
                    }
                    // SAFETY: `n` bytes were written by `read`.
                    unsafe { buf.assume_init(n) };
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
    fn poll_writev(&self, cx: &mut Context<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match sys_writev(guard.get_inner().as_raw_fd(), bufs) {
                Ok(n) => {
                    if n < total_len(bufs) {
                        guard.clear_ready();
                    }
                    return Poll::Ready(Ok(n));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
    fn shutdown_write(&self) -> io::Result<()> {
        match socket2::SockRef::from(self.fd.get_ref()).shutdown(std::net::Shutdown::Write) {
            Err(e) if e.raw_os_error() == Some(libc::ENOTCONN) => Ok(()),
            other => other,
        }
    }
}

/// Registers `fd` with the current core's reactor (edge-triggered, read and write interest).
pub(crate) fn register(fd: OwnedFd) -> io::Result<AsyncFd<OwnedFd>> {
    // SAFETY: the `OwnedFd` moves into the `AsyncFd`, so nothing else can close or replace the
    // descriptor while it is registered.
    Ok(unsafe { AsyncFd::register(fd) }?)
}

fn total_len(bufs: &[IoSlice<'_>]) -> usize {
    bufs.iter().map(|b| b.len()).sum()
}

fn cvt(r: isize) -> io::Result<usize> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

fn sys_read(fd: RawFd, ptr: *mut u8, len: usize) -> io::Result<usize> {
    // SAFETY: `ptr` is valid for `len` writable bytes.
    cvt(unsafe { libc::read(fd, ptr.cast(), len) })
}

fn sys_writev(fd: RawFd, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    // IoSlice is ABI-compatible with iovec; the kernel caps a call at IOV_MAX entries.
    let count = bufs.len().min(1024) as libc::c_int;
    // SAFETY: `bufs` points at `count` initialised iovecs.
    cvt(unsafe { libc::writev(fd, bufs.as_ptr().cast(), count) })
}

#[cfg(target_os = "linux")]
fn sys_sendfile(sock: RawFd, file: RawFd, offset: u64, len: usize) -> io::Result<usize> {
    let mut off = offset as libc::off_t;
    // SAFETY: plain syscall on two open descriptors.
    cvt(unsafe { libc::sendfile(sock, file, &mut off, len) })
}

/// Portable stand-in for development hosts: one pread and one write per call.
#[cfg(not(target_os = "linux"))]
fn sys_sendfile(sock: RawFd, file: RawFd, offset: u64, len: usize) -> io::Result<usize> {
    let mut chunk = [0u8; 16 * 1024];
    let len = len.min(chunk.len());
    // SAFETY: `chunk` is valid for `len` bytes.
    let n =
        cvt(unsafe { libc::pread(file, chunk.as_mut_ptr().cast(), len, offset as libc::off_t) })?;
    // SAFETY: the first `n` bytes of `chunk` are initialised.
    cvt(unsafe { libc::write(sock, chunk.as_ptr().cast(), n) })
}

/// A byte stream to a peer. Closed set, so drivers match instead of going through a trait
/// object, and the kernel-plaintext variants expose their fd for zero-copy paths.
pub(crate) enum Transport {
    Plain(Socket),
    /// TLS records handled by the kernel after the handshake; plaintext to us.
    Ktls(Socket),
    /// Userspace TLS over TCP (QUIC is separate), after the handshake.
    Tls(Box<TlsStream>),
}

thread_local! {
    /// Ciphertext buffers of this core's TLS connections, lent while records are in flight.
    static CIPHERTEXT: BufPool = BufPool::default();
}

/// A 64 KiB ciphertext buffer from this core's pool: room for three records of the largest
/// size a peer may send.
pub(crate) fn take_ciphertext() -> BytesMut {
    CIPHERTEXT.with(BufPool::take_large)
}

pub(crate) fn put_ciphertext(buf: BytesMut) {
    let _ = CIPHERTEXT.try_with(|pool| pool.put(buf));
}

/// Userspace TLS: records sealed and opened in place in pooled buffers by [`Session`]. An idle
/// connection holds no buffer, only its keys.
pub(crate) struct TlsStream {
    pub sock: Socket,
    session: Session,
    /// Received bytes: `plain` opened bytes the reader has not taken, the `trailer` of the
    /// record they came from, then sealed records (the last one possibly partial). `None` once
    /// all of it is taken.
    rx: Option<BytesMut>,
    plain: usize,
    trailer: usize,
    /// close_notify received: reads report the end of the stream.
    peer_closed: bool,
    /// Records not yet written, from the poll-based writer, which writes them on flush.
    tx: Option<BytesMut>,
    /// Offset in `tx` of the record the poll-based writer is filling, not sealed yet: the
    /// writes between two flushes share records.
    filling: Option<usize>,
    /// close_notify sealed.
    closing: bool,
}

impl TlsStream {
    /// `rx` holds whatever arrived after the handshake's last record, `tx` the records the
    /// handshake left to send, which go out with the first write.
    pub fn new(sock: Socket, session: Session, rx: BytesMut, tx: BytesMut) -> TlsStream {
        let mut stream = TlsStream {
            sock,
            session,
            rx: Some(rx),
            plain: 0,
            trailer: 0,
            peer_closed: false,
            tx: Some(tx),
            filling: None,
            closing: false,
        };
        stream.release_rx();
        if stream.tx.as_ref().is_some_and(|tx| tx.is_empty()) {
            put_ciphertext(stream.tx.take().expect("checked"));
        }
        stream
    }

    async fn read(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        if buf.capacity() - buf.len() < MIN_SPARE {
            buf.reserve(MIN_SPARE);
        }
        let n = std::future::poll_fn(|cx| {
            let mut out = ReadBuf::uninit(buf.spare_capacity_mut());
            ready!(self.poll_read_plain(cx, &mut out))?;
            Poll::Ready(Ok::<_, io::Error>(out.filled().len()))
        })
        .await?;
        // SAFETY: `poll_read_plain` initialised the first `n` bytes of the spare capacity.
        unsafe { buf.set_len(buf.len() + n) };
        Ok(n)
    }

    /// Fills `out` with plaintext: what is already opened, then every complete buffered record
    /// that fits, reading the socket only when nothing was delivered. Delivers nothing at the
    /// end of the stream (close_notify, or a TCP close between records).
    fn poll_read_plain(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        loop {
            if self.plain > 0 {
                let rx = self.rx.as_mut().expect("opened bytes live in rx");
                let n = self.plain.min(out.remaining());
                out.put_slice(&rx[..n]);
                rx.advance(n);
                self.plain -= n;
                if self.plain > 0 {
                    return Poll::Ready(Ok(()));
                }
                rx.advance(self.trailer);
                self.trailer = 0;
            }
            if out.remaining() == 0 || self.peer_closed {
                self.release_rx();
                return Poll::Ready(Ok(()));
            }
            if self.open_next()? {
                continue;
            }
            if out.filled().len() > before {
                self.release_rx();
                return Poll::Ready(Ok(()));
            }
            let rx = self.rx.get_or_insert_with(take_ciphertext);
            // Room for the largest record behind a partial one; with a pool buffer this moves
            // the partial record to the front instead of growing.
            if rx.capacity() - rx.len() < MAX_RECORD {
                rx.reserve(MAX_RECORD);
            }
            let mut spare = ReadBuf::uninit(rx.spare_capacity_mut());
            let polled = self.sock.poll_read_buf(cx, &mut spare);
            let n = spare.filled().len();
            // SAFETY: the kernel initialised `n` bytes of the spare capacity.
            unsafe { rx.set_len(rx.len() + n) };
            match polled {
                Poll::Ready(result) => result?,
                Poll::Pending => {
                    // A reader parked on an idle connection (the h2 driver) holds no buffer.
                    self.release_rx();
                    return Poll::Pending;
                }
            }
            if n == 0 {
                if rx.is_empty() {
                    self.release_rx();
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TCP closed inside a TLS record",
                )));
            }
        }
    }

    /// Opens the record at the front of `rx` if all of it is there. False when there is none.
    fn open_next(&mut self) -> io::Result<bool> {
        let Some(rx) = self.rx.as_mut() else {
            return Ok(false);
        };
        let opened = match record_len(rx) {
            Ok(None) => return Ok(false),
            Ok(Some(len)) => self
                .session
                .open(&mut rx[..len])
                .map(|opened| (opened, len)),
            Err(e) => Err(e),
        };
        let (opened, len) = opened.map_err(|e| self.fail(e))?;
        let rx = self.rx.as_mut().expect("checked");
        match opened {
            Opened::Data(range) => {
                rx.advance(range.start);
                self.plain = range.len();
                self.trailer = len - range.end;
            }
            Opened::Nothing => rx.advance(len),
            Opened::Closed => {
                rx.clear();
                self.peer_closed = true;
            }
        }
        Ok(true)
    }

    /// Answers a record-layer error with its fatal alert, in one write that never waits, and
    /// ends the stream: nothing is sealed after it.
    fn fail(&mut self, e: rustls::Error) -> io::Error {
        if !self.closing {
            self.closing = true;
            let _ = self.seal_filling();
            let mut tx = self.tx.take().unwrap_or_else(take_ciphertext);
            if self.session.seal_fatal_alert(&mut tx, &e) {
                let _ = self.sock.try_write(&tx);
            }
            put_ciphertext(tx);
        }
        invalid(e)
    }

    /// True when a read returns without waiting for the socket.
    fn has_buffered(&self) -> bool {
        self.plain > 0
            || self.peer_closed
            || self
                .rx
                .as_deref()
                .is_some_and(|rx| !matches!(record_len(rx), Ok(None)))
    }

    fn release_rx(&mut self) {
        if self.plain == 0 && self.rx.as_ref().is_some_and(|rx| rx.is_empty()) {
            put_ciphertext(self.rx.take().expect("checked"));
        }
    }

    /// Seals and writes all of `bufs` after the records already queued, a pool buffer of
    /// records per writev. Not cancel-safe: records sealed and then dropped unsent leave the
    /// peer unable to read what follows.
    async fn write_all_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        if self.closing {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.seal_filling()?;
        let total = total_len(bufs);
        let mut tx = self.tx.take().unwrap_or_else(take_ciphertext);
        let mut sealed = 0;
        let result = async {
            loop {
                sealed += self.session.seal(&mut tx, bufs, sealed).map_err(invalid)?;
                self.sock
                    .write_all_vectored(&mut [IoSlice::new(&tx)])
                    .await?;
                tx.clear();
                if sealed == total {
                    return Ok(());
                }
            }
        }
        .await;
        put_ciphertext(tx);
        result
    }

    /// Adds what fits to the record being filled, writing nothing: a flush seals it and writes
    /// the records, so the frames of several writes leave in few records and one writev. A
    /// full buffer is written first.
    fn poll_write_plain(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if total_len(bufs) == 0 {
            return Poll::Ready(Ok(0));
        }
        loop {
            let tx = self.tx.get_or_insert_with(take_ciphertext);
            if self.filling.is_none() {
                self.filling = self.session.begin(tx).map_err(invalid)?;
            }
            if let Some(start) = self.filling {
                let (n, full) = self.session.fill(tx, start, bufs);
                if full {
                    self.seal_filling()?;
                }
                if n > 0 {
                    return Poll::Ready(Ok(n));
                }
            }
            ready!(self.poll_flush_tx(cx))?;
        }
    }

    fn seal_filling(&mut self) -> io::Result<()> {
        if let Some(start) = self.filling.take() {
            let tx = self.tx.as_mut().expect("a record being filled lives in tx");
            self.session.finish(tx, start).map_err(invalid)?;
        }
        Ok(())
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.seal_filling()?;
        let Some(tx) = self.tx.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        while !tx.is_empty() {
            match ready!(self.sock.poll_writev(cx, &[IoSlice::new(tx)]))? {
                0 => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                n => tx.advance(n),
            }
        }
        put_ciphertext(self.tx.take().expect("checked"));
        Poll::Ready(Ok(()))
    }

    /// Queues close_notify once, unless a fatal alert ended the stream.
    fn seal_close_notify(&mut self) -> io::Result<()> {
        if !self.closing {
            self.closing = true;
            self.seal_filling()?;
            let tx = self.tx.get_or_insert_with(take_ciphertext);
            self.session.seal_close_notify(tx).map_err(invalid)?;
        }
        Ok(())
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.seal_close_notify()?;
        ready!(self.poll_flush_tx(cx))?;
        Poll::Ready(self.sock.shutdown_write())
    }

    /// close_notify and FIN in one attempt that never waits: a peer that stopped reading must
    /// not hold the connection open.
    fn close(&mut self) {
        if self.seal_close_notify().is_ok()
            && let Some(tx) = self.tx.as_ref()
        {
            let _ = self.sock.try_write(tx);
        }
        let _ = self.sock.shutdown_write();
    }
}

impl Drop for TlsStream {
    fn drop(&mut self) {
        if let Some(rx) = self.rx.take() {
            put_ciphertext(rx);
        }
        if let Some(tx) = self.tx.take() {
            put_ciphertext(tx);
        }
    }
}

fn invalid(e: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

impl Transport {
    pub async fn read(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.read(buf).await,
            Transport::Tls(tls) => tls.read(buf).await,
        }
    }
    pub async fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.write_all_vectored(bufs).await,
            Transport::Tls(tls) => tls.write_all_vectored(bufs).await,
        }
    }
    /// Waits until a read would not wait. Holds no buffer while waiting.
    pub async fn readable(&self) -> io::Result<()> {
        match self {
            Transport::Tls(tls) if tls.has_buffered() => Ok(()),
            _ => self.socket().readable().await,
        }
    }
    /// `Some` when bytes on the fd are the application's plaintext (cleartext or kTLS), i.e.
    /// sendfile/splice may target or source it.
    pub fn plaintext_fd(&self) -> Option<BorrowedFd<'_>> {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => Some(sock.fd()),
            Transport::Tls(_) => None,
        }
    }
    pub fn socket(&self) -> &Socket {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock,
            Transport::Tls(tls) => &tls.sock,
        }
    }
    /// Graceful close: TLS close_notify where applicable, then shutdown(WR).
    pub async fn close(self) {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => {
                let _ = sock.shutdown_write();
            }
            Transport::Tls(mut tls) => tls.close(),
        }
    }
}

// Poll-based IO for the h2 crate, which drives its connection through tokio's traits.
impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.poll_read_buf(cx, buf),
            Transport::Tls(tls) => tls.poll_read_plain(cx, buf),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[IoSlice::new(buf)])
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.poll_writev(cx, bufs),
            Transport::Tls(tls) => tls.poll_write_plain(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(_) | Transport::Ktls(_) => Poll::Ready(Ok(())),
            Transport::Tls(tls) => tls.poll_flush_tx(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Transport::Plain(sock) | Transport::Ktls(sock) => Poll::Ready(sock.shutdown_write()),
            Transport::Tls(tls) => tls.poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn connect_write_and_read_round_trip() {
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        runtime().block_on(async {
            let mut sock = Socket::connect(addr).await.unwrap();
            let (mut remote, _) = peer.accept().unwrap();
            assert!(socket2::SockRef::from(&sock.fd()).tcp_nodelay().unwrap());

            sock.write_all_vectored(&mut [
                IoSlice::new(b"GET / HTTP/1.1\r\n"),
                IoSlice::new(b""),
                IoSlice::new(b"Host: a\r\n\r\n"),
            ])
            .await
            .unwrap();
            let mut got = [0u8; 27];
            remote.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");

            remote
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .unwrap();
            let mut buf = BytesMut::new();
            while buf.len() < 27 {
                assert!(sock.read(&mut buf).await.unwrap() > 0);
            }
            assert_eq!(&buf[..], b"HTTP/1.1 204 No Content\r\n\r\n");
            assert!(buf.capacity() >= MIN_SPARE, "read grows an empty buffer");

            drop(remote);
            assert_eq!(sock.read(&mut buf).await.unwrap(), 0, "EOF");
        });
    }

    #[test]
    fn connect_refused_is_an_error() {
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let err = runtime()
            .block_on(Socket::connect(addr))
            .err()
            .expect("nothing listens there");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn large_write_waits_for_a_slow_reader() {
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        let payload: Vec<u8> = (0..8 << 20).map(|i: u32| i as u8).collect();
        let expected = payload.clone();
        let reader = std::thread::spawn(move || {
            let (mut remote, _) = peer.accept().unwrap();
            std::thread::sleep(Duration::from_millis(100));
            let mut got = Vec::new();
            remote.read_to_end(&mut got).unwrap();
            got
        });
        runtime().block_on(async {
            let mut sock = Socket::connect(addr).await.unwrap();
            let (a, b) = payload.split_at(3 << 20);
            sock.write_all_vectored(&mut [IoSlice::new(a), IoSlice::new(b)])
                .await
                .unwrap();
            Transport::Plain(sock).close().await;
        });
        assert!(reader.join().unwrap() == expected, "every byte, in order");
    }

    #[test]
    fn hung_up_or_readable_reports_peer_activity_without_reading() {
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        runtime().block_on(async {
            let sock = Socket::connect(addr).await.unwrap();
            let (remote, _) = peer.accept().unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(!sock.hung_up_or_readable(), "a quiet idle connection");
            drop(remote);
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(sock.hung_up_or_readable(), "the peer closed");
        });
    }

    #[test]
    fn sendfile_sends_the_range_and_stops_at_end_of_file() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"0123456789abcdefghij").unwrap();
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        runtime().block_on(async {
            let mut sock = Socket::connect(addr).await.unwrap();
            let (mut remote, _) = peer.accept().unwrap();
            assert_eq!(sock.sendfile(file.as_fd(), 3, 10).await.unwrap(), 10);
            let mut got = [0u8; 10];
            remote.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"3456789abc");
            assert_eq!(
                sock.sendfile(file.as_fd(), 15, 100).await.unwrap(),
                5,
                "a range past the end sends what exists"
            );
            let mut got = [0u8; 5];
            remote.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"fghij");
        });
    }

    #[test]
    fn transport_poll_io_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let peer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = peer.local_addr().unwrap();
        runtime().block_on(async {
            let mut io = Transport::Plain(Socket::connect(addr).await.unwrap());
            let (mut remote, _) = peer.accept().unwrap();
            io.write_all(b"ping").await.unwrap();
            let mut got = [0u8; 4];
            remote.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"ping");
            remote.write_all(b"pong").unwrap();
            let mut got = [0u8; 4];
            io.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"pong");
            io.shutdown().await.unwrap();
            let mut rest = Vec::new();
            remote.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty(), "shutdown sends FIN");
        });
    }
}
