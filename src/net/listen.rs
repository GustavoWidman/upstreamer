//! Listeners. Every core binds its own socket for every address (SO_REUSEPORT), so the kernel
//! spreads connections across cores and no accept is shared. TCP sockets: TCP_DEFER_ACCEPT
//! (wake only when the client sent data), TCP_FASTOPEN, backlog 4096, IPV6_V6ONLY on `[::]`.
//! UDP (QUIC): SO_REUSEPORT, UDP_GRO, large rcvbuf where permitted.
//!
//! Planned hooks: `SO_ATTACH_REUSEPORT_CBPF` returning the receiving CPU (connections stay
//! on the core whose softirq handled them), and an eBPF program steering QUIC packets by the
//! core index in the connection ID.

use crate::net::Socket;
use crate::plan::{ListenerKey, ListenerKind};
use std::io;
use std::net::SocketAddr;
use std::os::fd::OwnedFd;

pub(crate) struct Listener {
    pub key: ListenerKey,
    pub fd: tokio::io::unix::AsyncFd<OwnedFd>,
}

/// Binds one core's socket for `addr`. Needs CAP_NET_BIND_SERVICE for ports < 1024 (ambient
/// capability in the systemd unit).
pub(crate) fn bind(addr: SocketAddr, kind: ListenerKind) -> io::Result<OwnedFd> {
    todo!()
}

impl Listener {
    /// accept4(SOCK_NONBLOCK | SOCK_CLOEXEC); TCP_NODELAY and SO_KEEPALIVE set on the result.
    pub async fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        todo!()
    }
}

/// Builds the quinn endpoint for this core over its own UDP socket.
pub(crate) fn quic_endpoint(
    fd: OwnedFd,
    config: quinn::ServerConfig,
) -> io::Result<quinn::Endpoint> {
    todo!()
}
