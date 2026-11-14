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
use socket2::{Domain, Protocol, SockAddr, TcpKeepalive, Type};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

const BACKLOG: i32 = 4096;
/// Pending TCP Fast Open requests per listener.
const FASTOPEN_QUEUE: libc::c_int = 256;
/// Probes on otherwise silent connections, so a vanished peer of a tunnel (WebSocket, DERP)
/// is noticed within about two minutes.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_PROBES: u32 = 4;
const UDP_BUFFER: usize = 4 * 1024 * 1024;

pub(crate) struct Listener {
    pub key: ListenerKey,
    pub fd: tokio::io::unix::AsyncFd<OwnedFd>,
}

/// Binds one core's socket for `addr`. Needs CAP_NET_BIND_SERVICE for ports < 1024 (ambient
/// capability in the systemd unit).
pub(crate) fn bind(addr: SocketAddr, kind: ListenerKind) -> io::Result<OwnedFd> {
    let domain = Domain::for_address(addr);
    let sock = match kind {
        ListenerKind::Http | ListenerKind::Https => {
            socket2::Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?
        }
        ListenerKind::Quic => socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?,
    };
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    match kind {
        ListenerKind::Http | ListenerKind::Https => {
            // Accepted sockets inherit these from the listener, so accept costs no setsockopt.
            sock.set_tcp_nodelay(true)?;
            sock.set_tcp_keepalive(&keepalive())?;
            #[cfg(target_os = "linux")]
            {
                setsockopt_int(&sock, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 1)?;
                // Best effort: the sysctl may disable server-side Fast Open.
                let _ =
                    setsockopt_int(&sock, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, FASTOPEN_QUEUE);
            }
            sock.bind(&addr.into())?;
            sock.listen(BACKLOG)?;
        }
        ListenerKind::Quic => {
            // Best effort: above net.core.rmem_max the kernel caps or refuses the size.
            let _ = sock.set_recv_buffer_size(UDP_BUFFER);
            let _ = sock.set_send_buffer_size(UDP_BUFFER);
            sock.bind(&addr.into())?;
        }
    }
    Ok(sock.into())
}

fn keepalive() -> TcpKeepalive {
    TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_PROBES)
}

#[cfg(target_os = "linux")]
fn setsockopt_int(
    sock: &socket2::Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `value` outlives the call and its size is passed.
    let r = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl Listener {
    /// Registers a socket from [`bind`] with the current core's reactor.
    pub fn new(key: ListenerKey, fd: OwnedFd) -> io::Result<Listener> {
        Ok(Listener {
            key,
            fd: crate::net::register(fd)?,
        })
    }
    /// accept4(SOCK_NONBLOCK | SOCK_CLOEXEC); TCP_NODELAY and SO_KEEPALIVE come from the
    /// listener.
    pub async fn accept(&self) -> io::Result<(Socket, SocketAddr)> {
        loop {
            let mut guard = self.fd.readable().await?;
            match accept(guard.get_inner().as_raw_fd()) {
                Ok((fd, addr)) => {
                    let remote = addr
                        .as_socket()
                        .ok_or_else(|| io::Error::other("accepted a non-IP peer"))?;
                    return Ok((Socket::from_fd(fd)?, remote));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn accept(listener: std::os::fd::RawFd) -> io::Result<(OwnedFd, SockAddr)> {
    // SAFETY: `try_init` hands a zeroed storage and its length to accept4.
    unsafe {
        SockAddr::try_init(|storage, len| {
            let fd = libc::accept4(
                listener,
                storage.cast(),
                len,
                libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            );
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(OwnedFd::from_raw_fd(fd))
            }
        })
    }
}

/// Development hosts without accept4: accept, then flag the descriptor.
#[cfg(not(target_os = "linux"))]
fn accept(listener: std::os::fd::RawFd) -> io::Result<(OwnedFd, SockAddr)> {
    // SAFETY: `try_init` hands a zeroed storage and its length to accept.
    let (fd, addr) = unsafe {
        SockAddr::try_init(|storage, len| {
            let fd = libc::accept(listener, storage.cast(), len);
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(OwnedFd::from_raw_fd(fd))
            }
        })
    }?;
    let sock = socket2::SockRef::from(&fd);
    sock.set_nonblocking(true)?;
    sock.set_cloexec(true)?;
    Ok((fd, addr))
}

/// Builds the quinn endpoint for this core over its own UDP socket.
pub(crate) fn quic_endpoint(
    fd: OwnedFd,
    config: quinn::ServerConfig,
) -> io::Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| io::Error::other("no tokio runtime"))?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        std::net::UdpSocket::from(fd),
        runtime,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn accepted_sockets_inherit_listener_options() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = free.local_addr().unwrap();
        drop(free);
        let fd = bind(addr, ListenerKind::Http).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let key = ListenerKey {
                addr,
                kind: ListenerKind::Http,
            };
            let listener = Listener::new(key, fd).unwrap();
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(b"G").unwrap();
            let (sock, remote) = listener.accept().await.unwrap();
            assert_eq!(remote, client.local_addr().unwrap());
            let fd = sock.fd();
            let opts = socket2::SockRef::from(&fd);
            assert!(opts.tcp_nodelay().unwrap(), "TCP_NODELAY");
            assert!(opts.keepalive().unwrap(), "SO_KEEPALIVE");
        });
    }

    #[test]
    fn two_sockets_bind_one_address() {
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = free.local_addr().unwrap();
        drop(free);
        let _a = bind(addr, ListenerKind::Http).unwrap();
        let _b = bind(addr, ListenerKind::Http).unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        drop(udp);
        let _c = bind(addr, ListenerKind::Quic).unwrap();
        let _d = bind(addr, ListenerKind::Quic).unwrap();
    }

    #[test]
    fn ipv6_wildcard_is_v6_only() {
        let fd = bind("[::]:0".parse().unwrap(), ListenerKind::Http).unwrap();
        assert!(socket2::SockRef::from(&fd).only_v6().unwrap());
    }
}
