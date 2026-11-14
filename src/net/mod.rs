//! Sockets and transports. Our own socket type over `AsyncFd` instead of tokio's `TcpStream`,
//! for two reasons the hot path depends on:
//! - readiness is cleared by us after a short read or write (the edge-triggered rule nginx
//!   uses), so the read after a drained socket waits on epoll instead of costing an EAGAIN
//!   syscall;
//! - the raw fd is reachable for sendfile, splice and kTLS setsockopt, and an io_uring
//!   backend can replace the internals behind the same methods.

pub(crate) mod buf;
pub(crate) mod listen;

use bytes::BytesMut;
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
    /// Userspace rustls (QUIC is separate; this is TCP only). Server or client side.
    Tls(Box<TlsStream>),
}

/// Userspace TLS. The implementation drives rustls's unbuffered API so records are decrypted
/// and encrypted in our buffers (no per-record allocation inside rustls).
pub(crate) struct TlsStream {
    pub sock: Socket,
    pub conn: rustls::Connection,
    /// Ciphertext read buffer; released when the connection goes idle.
    pub rx: Option<BytesMut>,
}

impl Transport {
    pub async fn read(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.read(buf).await,
            Transport::Tls(_) => todo!("userspace TLS records"),
        }
    }
    pub async fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        match self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.write_all_vectored(bufs).await,
            Transport::Tls(_) => todo!("userspace TLS records"),
        }
    }
    pub async fn readable(&self) -> io::Result<()> {
        self.socket().readable().await
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
            Transport::Tls(_) => todo!("close_notify, then shutdown"),
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
        match &*self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.poll_read_buf(cx, buf),
            Transport::Tls(_) => todo!("userspace TLS records"),
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
        match &*self {
            Transport::Plain(sock) | Transport::Ktls(sock) => sock.poll_writev(cx, bufs),
            Transport::Tls(_) => todo!("userspace TLS records"),
        }
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &*self {
            Transport::Plain(_) | Transport::Ktls(_) => Poll::Ready(Ok(())),
            Transport::Tls(_) => todo!("flush buffered TLS records"),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &*self {
            Transport::Plain(sock) | Transport::Ktls(sock) => Poll::Ready(sock.shutdown_write()),
            Transport::Tls(_) => todo!("close_notify, then shutdown"),
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
