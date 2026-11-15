//! Clients that speak TLS, HTTP/2 and HTTP/3 to the proxy. Certificates are not verified (a
//! site without its certificate files answers with a self-signed one); the chain a server sent
//! is returned for tests that check which certificate is served.

use super::{PATIENCE, Reserved};
use bytes::{Buf, Bytes};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A loopback port free for TCP and UDP, held for TCP while the value lives.
pub fn reserve_udp() -> Reserved {
    loop {
        let port = Reserved::new();
        if std::net::UdpSocket::bind(port.addr).is_ok() {
            return port;
        }
    }
}

/// The certificate chain `addr` serves for `host`, from a full TLS handshake.
pub fn served_chain(addr: SocketAddr, host: &str) -> Vec<CertificateDer<'static>> {
    let io = TlsStream::connect_blocking(addr, host, &[b"http/1.1"]);
    io.tls
        .peer_certificates()
        .expect("the server sent certificates")
        .to_vec()
}

/// A status and a body.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// One `GET` over HTTP/1.1 on TLS, on a connection of its own; the response must carry a
/// Content-Length.
pub fn h1_tls_get(addr: SocketAddr, host: &str, path: &str) -> io::Result<Reply> {
    let mut io = TlsStream::connect_blocking_checked(addr, host, &[b"http/1.1"])?;
    io.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    io.flush()?;
    read_h1_response(&mut io)
}

/// One HTTP/1.1 response with a Content-Length from `io`.
pub fn read_h1_response(io: &mut impl Read) -> io::Result<Reply> {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16384];
    let end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match io.read(&mut chunk)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => raw.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::other(format!("not a status line: {head}")))?;
    let length: usize = super::header(&head, "content-length")
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| io::Error::other(format!("no Content-Length: {head}")))?;
    let mut body = raw.split_off(end);
    while body.len() < length {
        match io.read(&mut chunk)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            n => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    Ok(Reply { status, body })
}

/// An HTTP/2 connection; its connection task runs on the caller's tokio runtime.
pub struct H2 {
    pub send: h2::client::SendRequest<Bytes>,
    host: String,
    pub done: tokio::task::JoinHandle<Result<(), h2::Error>>,
}

impl H2 {
    pub async fn connect(addr: SocketAddr, host: &str) -> io::Result<H2> {
        let io = TlsStream::connect_tokio(addr, host, &[b"h2"])?;
        if io.tls.alpn_protocol() != Some(b"h2") {
            return Err(io::Error::other("ALPN did not choose h2"));
        }
        let (send, conn) = h2::client::handshake(io).await.map_err(io::Error::other)?;
        Ok(H2 {
            send,
            host: host.to_owned(),
            done: tokio::spawn(conn),
        })
    }

    /// Sends `GET path`; the returned future reads the whole response.
    pub async fn start_get(
        &mut self,
        path: &str,
    ) -> Result<impl Future<Output = Result<Reply, h2::Error>> + use<>, h2::Error> {
        std::future::poll_fn(|cx| self.send.poll_ready(cx)).await?;
        let request = http::Request::get(format!("https://{}{path}", self.host))
            .body(())
            .unwrap();
        let (response, _) = self.send.send_request(request, true)?;
        Ok(async move {
            let (parts, mut recv) = response.await?.into_parts();
            let mut body = Vec::new();
            while let Some(data) = recv.data().await {
                let data = data?;
                let _ = recv.flow_control().release_capacity(data.len());
                body.extend_from_slice(&data);
            }
            Ok(Reply {
                status: parts.status.as_u16(),
                body,
            })
        })
    }

    pub async fn get(&mut self, path: &str) -> Result<Reply, h2::Error> {
        self.start_get(path).await?.await
    }
}

/// An HTTP/3 connection on a UDP socket of its own.
pub struct H3 {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    pub endpoint: quinn::Endpoint,
    authority: String,
    /// Resolves with the error that ended the connection.
    pub closed: tokio::task::JoinHandle<h3::error::ConnectionError>,
}

impl H3 {
    pub async fn connect(addr: SocketAddr, host: &str) -> Result<H3, String> {
        let mut crypto = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider())))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
        let mut endpoint =
            quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).map_err(|e| e.to_string())?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
        let quic = endpoint
            .connect(addr, host)
            .map_err(|e| e.to_string())?
            .await
            .map_err(|e| e.to_string())?;
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(quic))
            .await
            .map_err(|e| e.to_string())?;
        let closed =
            tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
        Ok(H3 {
            send,
            endpoint,
            authority: format!("{host}:{}", addr.port()),
            closed,
        })
    }

    /// Sends `GET path`; the returned future reads the whole response.
    pub async fn start_get(
        &mut self,
        path: &str,
    ) -> Result<impl Future<Output = Result<Reply, String>> + use<>, String> {
        let request = http::Request::get(format!("https://{}{path}", self.authority))
            .body(())
            .unwrap();
        let mut stream = self
            .send
            .send_request(request)
            .await
            .map_err(|e| e.to_string())?;
        stream.finish().await.map_err(|e| e.to_string())?;
        Ok(async move {
            let response = stream.recv_response().await.map_err(|e| e.to_string())?;
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.map_err(|e| e.to_string())? {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            Ok(Reply {
                status: response.status().as_u16(),
                body,
            })
        })
    }

    pub async fn get(&mut self, path: &str) -> Result<Reply, String> {
        self.start_get(path).await?.await
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

pub fn client_config(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider())))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// A rustls client connection over a TCP socket: blocking for HTTP/1.1, and through tokio's
/// traits for the `h2` client.
pub struct TlsStream<S> {
    pub sock: S,
    pub tls: rustls::ClientConnection,
}

impl TlsStream<TcpStream> {
    pub fn connect_blocking(addr: SocketAddr, host: &str, alpn: &[&[u8]]) -> TlsStream<TcpStream> {
        TlsStream::connect_blocking_checked(addr, host, alpn).expect("a TLS handshake")
    }

    pub fn connect_blocking_checked(
        addr: SocketAddr,
        host: &str,
        alpn: &[&[u8]],
    ) -> io::Result<TlsStream<TcpStream>> {
        let name = ServerName::try_from(host.to_owned()).unwrap();
        let mut tls = rustls::ClientConnection::new(client_config(alpn), name).unwrap();
        let mut sock = TcpStream::connect(addr)?;
        sock.set_read_timeout(Some(PATIENCE))?;
        while tls.is_handshaking() {
            tls.complete_io(&mut sock)?;
        }
        Ok(TlsStream { sock, tls })
    }
}

impl Read for TlsStream<TcpStream> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.tls, &mut self.sock).read(buf)
    }
}

impl Write for TlsStream<TcpStream> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        rustls::Stream::new(&mut self.tls, &mut self.sock).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        rustls::Stream::new(&mut self.tls, &mut self.sock).flush()
    }
}

impl TlsStream<tokio::net::TcpStream> {
    /// Handshakes blocking, then hands the socket to tokio.
    pub fn connect_tokio(
        addr: SocketAddr,
        host: &str,
        alpn: &[&[u8]],
    ) -> io::Result<TlsStream<tokio::net::TcpStream>> {
        let TlsStream { sock, tls } = TlsStream::connect_blocking_checked(addr, host, alpn)?;
        sock.set_nonblocking(true)?;
        Ok(TlsStream {
            sock: tokio::net::TcpStream::from_std(sock)?,
            tls,
        })
    }

    /// Writes out every record rustls has ready.
    fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tls.wants_write() {
            let mut io = Polled {
                sock: &mut self.sock,
                cx,
            };
            match self.tls.write_tls(&mut io) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A tokio socket as `Read + Write` for rustls, inside a poll: not ready is `WouldBlock`.
struct Polled<'a, 'b> {
    sock: &'a mut tokio::net::TcpStream,
    cx: &'a mut Context<'b>,
}

impl Read for Polled<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut *self.sock).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl Write for Polled<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.sock).poll_write(self.cx, buf) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsyncRead for TlsStream<tokio::net::TcpStream> {
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
            if let Poll::Ready(Err(e)) = this.poll_send(cx) {
                return Poll::Ready(Err(e));
            }
            let mut io = Polled {
                sock: &mut this.sock,
                cx,
            };
            match this.tls.read_tls(&mut io) {
                Ok(0) => return Poll::Ready(Ok(())),
                Ok(_) => {
                    this.tls.process_new_packets().map_err(io::Error::other)?;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
    }
}

impl AsyncWrite for TlsStream<tokio::net::TcpStream> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            let n = this.tls.writer().write(buf)?;
            if n > 0 {
                if let Poll::Ready(Err(e)) = this.poll_send(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(n));
            }
            ready!(this.poll_send(cx))?;
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_send(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tls.send_close_notify();
        ready!(this.poll_send(cx))?;
        Pin::new(&mut this.sock).poll_shutdown(cx)
    }
}

#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
