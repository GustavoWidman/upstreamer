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
use std::os::fd::{BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A nonblocking TCP socket registered with the core's reactor (edge-triggered).
pub(crate) struct Socket {
    fd: AsyncFd<OwnedFd>,
}

impl Socket {
    pub fn from_fd(fd: OwnedFd) -> io::Result<Socket> {
        todo!()
    }
    /// Nonblocking connect to an origin, TCP_NODELAY set; resolves when the connection is
    /// established (the caller bounds it with the dial timeout).
    pub async fn connect(addr: SocketAddr) -> io::Result<Socket> {
        todo!()
    }
    /// Reads into the spare capacity of `buf` (growing it to at least 4 KiB spare). `Ok(0)` is
    /// EOF. A read shorter than the spare capacity clears read readiness.
    pub async fn read(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        todo!()
    }
    /// Writes all of `bufs` (writev), waiting on writability as needed.
    pub async fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        todo!()
    }
    /// Waits for readability without reading (idle keep-alive connections hold no buffer).
    pub async fn readable(&self) -> io::Result<()> {
        todo!()
    }
    /// Readiness says the peer closed or sent bytes (pooled upstream liveness check): no
    /// syscall.
    pub fn hung_up_or_readable(&self) -> bool {
        todo!()
    }
    pub async fn sendfile(
        &mut self,
        file: BorrowedFd<'_>,
        offset: u64,
        len: u64,
    ) -> io::Result<u64> {
        todo!()
    }
    pub fn fd(&self) -> BorrowedFd<'_> {
        todo!()
    }
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
        todo!()
    }
    pub async fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        todo!()
    }
    pub async fn readable(&self) -> io::Result<()> {
        todo!()
    }
    /// `Some` when bytes on the fd are the application's plaintext (cleartext or kTLS), i.e.
    /// sendfile/splice may target or source it.
    pub fn plaintext_fd(&self) -> Option<BorrowedFd<'_>> {
        todo!()
    }
    pub fn socket(&self) -> &Socket {
        todo!()
    }
    /// Graceful close: TLS close_notify where applicable, then shutdown(WR).
    pub async fn close(self) {
        todo!()
    }
}

// Poll-based IO for the h2 crate, which drives its connection through tokio's traits.
impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        todo!()
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        todo!()
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        todo!()
    }
    fn is_write_vectored(&self) -> bool {
        true
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!()
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        todo!()
    }
}
