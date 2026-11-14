//! TLS towards an origin (`https://` upstreams). The stream drives a rustls client connection
//! through its buffered API: rustls owns the record buffers, and this module moves ciphertext
//! between them and the socket. Origins behind TLS are rare and local (an admin interface
//! with a self-signed certificate), so this path favours being small over being
//! allocation-free.

use crate::net::{Socket, Transport};
use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct ClientStream {
    io: Transport,
    tls: ClientConnection,
}

impl ClientStream {
    /// Handshakes on a connected socket. The caller bounds it with the dial timeout.
    pub async fn connect(
        sock: Socket,
        config: Arc<rustls::ClientConfig>,
        name: ServerName<'static>,
    ) -> io::Result<ClientStream> {
        let tls = ClientConnection::new(config, name).map_err(io::Error::other)?;
        let mut stream = ClientStream {
            io: Transport::Plain(sock),
            tls,
        };
        poll_fn(|cx| stream.poll_handshake(cx)).await?;
        Ok(stream)
    }

    pub fn socket(&self) -> &Socket {
        self.io.socket()
    }

    fn poll_handshake(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tls.is_handshaking() {
            ready!(self.poll_send(cx))?;
            if self.tls.is_handshaking() && ready!(self.poll_receive(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
        self.poll_send(cx)
    }

    /// Writes the ciphertext rustls holds to the socket.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tls.wants_write() {
            let mut socket = Blocking {
                io: &mut self.io,
                cx,
            };
            match self.tls.write_tls(&mut socket) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Reads ciphertext from the socket into rustls and decrypts it. `Ok(0)` when the origin
    /// closed the socket.
    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut socket = Blocking {
            io: &mut self.io,
            cx,
        };
        let n = match self.tls.read_tls(&mut socket) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if let Err(e) = self.tls.process_new_packets() {
            // The alert rustls queued for the origin goes out if the socket takes it now.
            let _ = self.poll_send(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e)));
        }
        Poll::Ready(Ok(n))
    }
}

/// The socket as the blocking reader and writer rustls expects, inside one poll: a wait
/// becomes `WouldBlock`, with the task's waker registered.
struct Blocking<'a, 'b> {
    io: &'a mut Transport,
    cx: &'a mut Context<'b>,
}

impl Read for Blocking<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut dst = ReadBuf::new(buf);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut dst) {
            Poll::Ready(Ok(())) => Ok(dst.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl Write for Blocking<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write_vectored(self.cx, bufs) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for ClientStream {
    /// Zero bytes filled is the end of the stream, with or without the origin's close_notify:
    /// the message framing above decides whether the response was complete.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match this.tls.reader().read(buf.initialize_unfilled()) {
                Ok(n) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Poll::Ready(Ok(())),
                Err(e) => return Poll::Ready(Err(e)),
            }
            // Ciphertext still held here (the request, a key update) goes out before waiting
            // for the origin's answer to it.
            ready!(this.poll_send(cx))?;
            if ready!(this.poll_receive(cx))? == 0 {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl AsyncWrite for ClientStream {
    /// Accepts plaintext into rustls and pushes ciphertext out. Bytes the socket does not
    /// take yet stay in rustls until `poll_flush` or the next read.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Sending first keeps the ciphertext rustls buffers bounded by one write.
        ready!(this.poll_send(cx))?;
        let n = this.tls.writer().write(buf)?;
        if let Poll::Ready(Err(e)) = this.poll_send(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tls.writer().flush()?;
        this.poll_send(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tls.send_close_notify();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
