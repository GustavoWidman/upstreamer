//! A connection to an origin and the byte stream under it.

use super::timer::Deadline;
use super::tls::ClientStream;
use crate::net::Transport;
use crate::plan::OriginId;
use bytes::BytesMut;
use std::future::poll_fn;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Spare capacity a read is given at least.
const MIN_SPARE: usize = 4096;

/// A connection to an origin. Owned by exactly one request while checked out, by the core's
/// pool while idle; never shared.
pub(crate) struct UpstreamConn {
    pub io: UpstreamIo,
    /// Bytes read from the origin and not yet consumed. Lent from the core's buffer pool
    /// while checked out; an idle connection holds an empty buffer without an allocation.
    pub buf: BytesMut,
    pub origin: OriginId,
    /// The `Upstreams` epoch `origin` indexes.
    pub epoch: crate::upstream::Epoch,
    /// `Some` while a pool target's request holds the connection.
    pub busy: Option<super::pool::Busy>,
    pub idle_since: Instant,
    /// Response-header timeout, then tunnel idle timeout.
    pub watch: Deadline,
}

/// The stream to an origin: cleartext, or TLS driven here through rustls's buffered
/// connection.
pub(crate) enum UpstreamIo {
    Plain(Transport),
    Tls(Box<ClientStream>),
}

impl UpstreamIo {
    /// Reads into the spare capacity of `buf`. `Ok(0)` is the end of the stream. Dropping the
    /// future loses no bytes.
    pub async fn read(&mut self, buf: &mut BytesMut) -> io::Result<usize> {
        match self {
            UpstreamIo::Plain(io) => io.read(buf).await,
            UpstreamIo::Tls(tls) => poll_fn(|cx| poll_read_buf(&mut **tls, cx, buf)).await,
        }
    }

    pub async fn write_all_vectored(&mut self, bufs: &mut [IoSlice<'_>]) -> io::Result<()> {
        match self {
            UpstreamIo::Plain(io) => io.write_all_vectored(bufs).await,
            UpstreamIo::Tls(tls) => {
                for buf in bufs.iter() {
                    let mut rest: &[u8] = buf;
                    while !rest.is_empty() {
                        let n = poll_fn(|cx| Pin::new(&mut **tls).poll_write(cx, rest)).await?;
                        rest = &rest[n..];
                    }
                }
                poll_fn(|cx| Pin::new(&mut **tls).poll_flush(cx)).await
            }
        }
    }

    /// Whether the origin closed or sent bytes while the connection was idle, from the
    /// reactor's readiness: no syscall.
    pub fn hung_up_or_readable(&self) -> bool {
        match self {
            UpstreamIo::Plain(io) => io.socket().hung_up_or_readable(),
            UpstreamIo::Tls(tls) => tls.socket().hung_up_or_readable(),
        }
    }
}

impl AsyncRead for UpstreamIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(io) => Pin::new(io).poll_read(cx, buf),
            UpstreamIo::Tls(tls) => Pin::new(&mut **tls).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UpstreamIo::Plain(io) => Pin::new(io).poll_write(cx, buf),
            UpstreamIo::Tls(tls) => Pin::new(&mut **tls).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(io) => Pin::new(io).poll_flush(cx),
            UpstreamIo::Tls(tls) => Pin::new(&mut **tls).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UpstreamIo::Plain(io) => Pin::new(io).poll_shutdown(cx),
            UpstreamIo::Tls(tls) => Pin::new(&mut **tls).poll_shutdown(cx),
        }
    }
}

/// One read into the spare capacity of `buf`, growing it to at least 4 KiB spare.
pub(crate) fn poll_read_buf<R: AsyncRead + Unpin + ?Sized>(
    io: &mut R,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
) -> Poll<io::Result<usize>> {
    if buf.capacity() - buf.len() < MIN_SPARE {
        buf.reserve(MIN_SPARE);
    }
    let mut dst = ReadBuf::uninit(buf.spare_capacity_mut());
    ready!(Pin::new(io).poll_read(cx, &mut dst))?;
    let n = dst.filled().len();
    // SAFETY: the reader initialised the `n` bytes it reports as filled.
    unsafe { buf.set_len(buf.len() + n) };
    Poll::Ready(Ok(n))
}
