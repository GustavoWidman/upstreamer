//! Kernel TLS offload after a rustls handshake. Supported: TLS 1.3 and 1.2 with AES-128-GCM,
//! AES-256-GCM, ChaCha20-Poly1305 (Linux >= 5.11).
//!
//! Why: after offload the connection is a plain socket to userspace. sendfile(2) and splice(2)
//! work through TLS (static files and large proxied bodies without userspace copies), and an
//! idle TLS connection holds no rustls state at all (the 10k idle connections benchmark).
//!
//! Sequence: handshake completes -> flush NewSessionTicket and any pending records ->
//! `dangerous_extract_secrets` -> setsockopt(TCP_ULP, "tls") -> TLS_TX and TLS_RX crypto info.
//! Non-application records arriving later (alerts, KeyUpdate) surface as a control message on
//! recvmsg: alerts close the connection; KeyUpdate is handled by the kernel where supported,
//! else the connection is closed gracefully (clients practically never send it).
//!
//! Failure at any step before TLS_RX is set falls back to userspace rustls on the same
//! connection; the decision is per connection and logged once per process.

use crate::net::{Socket, Transport};

#[derive(Debug)]
pub(crate) enum OffloadError {
    /// ENOENT/ENOPROTOOPT from TCP_ULP: no `tls` module; the NixOS module loads it.
    Unsupported,
    Cipher,
    Pending,
    Io(std::io::Error),
}

/// On success the caller drops the rustls connection and uses the socket directly. On
/// failure, the untouched connection is handed back for userspace TLS.
pub(crate) fn offload(
    sock: &Socket,
    conn: Box<rustls::ServerConnection>,
) -> Result<(), (OffloadError, Box<rustls::ServerConnection>)> {
    todo!()
}

/// When a TLS connection moves to kTLS. Offload costs three setsockopts and a kernel AEAD
/// context, which a connection that serves one request and closes (the handshake-heavy
/// benchmark) would pay for nothing. So: when the connection first goes idle after a response
/// (from then on it holds no rustls state while idle), or right before a body that would use
/// sendfile/splice. Measurements may move this; callers only ask.
pub(crate) enum OffloadPoint {
    IdleAfterResponse,
    BeforeZeroCopyBody,
}

/// Offloads if `transport` is userspace TLS, quiescent (no buffered records either way) and
/// the kernel supports the cipher; leaves it unchanged otherwise.
pub(crate) fn offload_point(transport: &mut Transport, at: OffloadPoint) {
    todo!()
}
