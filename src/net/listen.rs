//! Listeners. Every core binds its own socket for every address (SO_REUSEPORT), so the kernel
//! spreads connections across cores and no accept is shared. TCP sockets: TCP_DEFER_ACCEPT
//! (wake only when the client sent data), TCP_FASTOPEN, backlog 4096, IPV6_V6ONLY on `[::]`.
//! UDP (QUIC): SO_REUSEPORT, UDP_GRO, large rcvbuf where permitted.
//!
//! A socket need not be bound by the process that serves it: [`Inherited`] is one this process
//! was given by the process it takes over from, with its queue of connections.
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
use std::sync::{Arc, Weak};
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

/// What a listening socket is to the kernel. Cleartext and TLS listeners are the same kind of
/// socket, so a socket bound for one can serve the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SocketKind {
    Tcp,
    Udp,
}

impl SocketKind {
    pub fn of(kind: ListenerKind) -> SocketKind {
        match kind {
            ListenerKind::Http | ListenerKind::Https => SocketKind::Tcp,
            ListenerKind::Quic => SocketKind::Udp,
        }
    }
}

pub(crate) struct Listener {
    pub key: ListenerKey,
    pub fd: tokio::io::unix::AsyncFd<OwnedFd>,
}

/// Binds one core's socket for `addr`. Needs CAP_NET_BIND_SERVICE for ports < 1024 (ambient
/// capability in the systemd unit).
pub(crate) fn bind(addr: SocketAddr, kind: ListenerKind) -> io::Result<OwnedFd> {
    let transport = SocketKind::of(kind);
    let domain = Domain::for_address(addr);
    let sock = match transport {
        SocketKind::Tcp => socket2::Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?,
        SocketKind::Udp => socket2::Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?,
    };
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    if addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.bind(&addr.into())?;
    tune(&sock, transport)?;
    Ok(sock.into())
}

/// The options of a bound socket, and `listen` for TCP. Every one of them can be set again on
/// a socket that already listens, which is how an inherited socket gets this build's values.
fn tune(sock: &socket2::Socket, transport: SocketKind) -> io::Result<()> {
    match transport {
        SocketKind::Tcp => {
            // Accepted sockets inherit these from the listener, so accept costs no setsockopt.
            sock.set_tcp_nodelay(true)?;
            sock.set_tcp_keepalive(&keepalive())?;
            #[cfg(target_os = "linux")]
            {
                setsockopt_int(sock, libc::IPPROTO_TCP, libc::TCP_DEFER_ACCEPT, 1)?;
                // Best effort: the sysctl may disable server-side Fast Open.
                let _ = setsockopt_int(sock, libc::IPPROTO_TCP, libc::TCP_FASTOPEN, FASTOPEN_QUEUE);
            }
            sock.listen(BACKLOG)
        }
        SocketKind::Udp => {
            // Best effort: above net.core.rmem_max the kernel caps or refuses the size.
            let _ = sock.set_recv_buffer_size(UDP_BUFFER);
            let _ = sock.set_send_buffer_size(UDP_BUFFER);
            Ok(())
        }
    }
}

/// A bound socket this process did not bind: the process it takes over from handed it down,
/// so the connections and datagrams queued on it are served rather than lost.
#[derive(Debug)]
pub(crate) struct Inherited {
    pub transport: SocketKind,
    pub addr: SocketAddr,
    pub fd: OwnedFd,
}

impl Inherited {
    /// Reads from the socket itself what it is: a listening TCP socket or a UDP socket, bound
    /// to an IP address. Anything else is an error. The descriptor is made non-blocking and
    /// close-on-exec, as [`bind`] makes its own.
    pub fn identify(fd: OwnedFd) -> io::Result<Inherited> {
        let sock = socket2::Socket::from(fd);
        let kind = sock.r#type()?;
        let transport = if kind == Type::STREAM {
            SocketKind::Tcp
        } else if kind == Type::DGRAM {
            SocketKind::Udp
        } else {
            return Err(io::Error::other("neither a stream nor a datagram socket"));
        };
        let addr = sock
            .local_addr()?
            .as_socket()
            .filter(|addr| addr.port() != 0)
            .ok_or_else(|| io::Error::other("not bound to an IP address and port"))?;
        #[cfg(target_os = "linux")]
        if transport == SocketKind::Tcp
            && getsockopt_int(&sock, libc::SOL_SOCKET, libc::SO_ACCEPTCONN)? == 0
        {
            return Err(io::Error::other("a TCP socket that does not listen"));
        }
        sock.set_nonblocking(true)?;
        sock.set_cloexec(true)?;
        Ok(Inherited {
            transport,
            addr,
            fd: sock.into(),
        })
    }

    /// Whether this socket can serve the listener `key`.
    pub fn serves(&self, key: ListenerKey) -> bool {
        self.transport == SocketKind::of(key.kind) && self.addr == key.addr
    }

    /// The socket as [`bind`] would have left it, with this build's options.
    pub fn adopt(self) -> io::Result<OwnedFd> {
        let sock = socket2::Socket::from(self.fd);
        tune(&sock, self.transport)?;
        Ok(sock.into())
    }
}

#[cfg(test)]
impl Inherited {
    /// A socket for a `kind` listener on a loopback port the kernel picks. The port is this
    /// socket's from the start, where a port found free and bound afterwards can go to
    /// another test in between.
    pub fn fresh(kind: ListenerKind) -> Inherited {
        let any = "127.0.0.1:0".parse().unwrap();
        Inherited::identify(bind(any, kind).unwrap()).unwrap()
    }

    /// Another socket on this one's address, as another core's.
    pub fn sibling(&self, kind: ListenerKind) -> Inherited {
        Inherited::identify(bind(self.addr, kind).unwrap()).unwrap()
    }
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

#[cfg(target_os = "linux")]
fn getsockopt_int(
    sock: &socket2::Socket,
    level: libc::c_int,
    name: libc::c_int,
) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are valid out pointers of the sizes passed.
    let r = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &mut len,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
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

/// Builds the quinn endpoint for this core over its own UDP socket. The second value is
/// quinn's hold on the socket: it is gone once the endpoint, its connections and its driver
/// are, which is when nothing in this process reads the socket any more.
pub(crate) fn quic_endpoint(
    fd: OwnedFd,
    config: quinn::ServerConfig,
) -> io::Result<(quinn::Endpoint, Weak<dyn quinn::AsyncUdpSocket>)> {
    let runtime = quinn::default_runtime().ok_or_else(|| io::Error::other("no tokio runtime"))?;
    let socket = runtime.wrap_udp_socket(std::net::UdpSocket::from(fd))?;
    let io = Arc::downgrade(&socket);
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )?;
    Ok((endpoint, io))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn accepted_sockets_inherit_listener_options() {
        let Inherited { addr, fd, .. } = Inherited::fresh(ListenerKind::Http);
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
        let tcp = Inherited::fresh(ListenerKind::Http);
        let _second = bind(tcp.addr, ListenerKind::Http).unwrap();
        let udp = Inherited::fresh(ListenerKind::Quic);
        let _second = bind(udp.addr, ListenerKind::Quic).unwrap();
    }

    #[test]
    fn an_inherited_socket_is_identified_by_what_it_is_bound_to() {
        let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let bound = bind(any, ListenerKind::Https).unwrap();
        let addr = socket2::SockRef::from(&bound)
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap();
        let tcp = Inherited::identify(bound).unwrap();
        assert_eq!((tcp.transport, tcp.addr), (SocketKind::Tcp, addr));
        let key = |kind| ListenerKey { addr, kind };
        assert!(tcp.serves(key(ListenerKind::Http)) && tcp.serves(key(ListenerKind::Https)));
        assert!(!tcp.serves(key(ListenerKind::Quic)));
        let other = SocketAddr::new(addr.ip(), addr.port().wrapping_add(1));
        assert!(!tcp.serves(ListenerKey {
            addr: other,
            kind: ListenerKind::Http
        }));

        let udp = Inherited::identify(bind(any, ListenerKind::Quic).unwrap()).unwrap();
        assert_eq!(udp.transport, SocketKind::Udp);
        let key = |kind| ListenerKey {
            addr: udp.addr,
            kind,
        };
        assert!(udp.serves(key(ListenerKind::Quic)) && !udp.serves(key(ListenerKind::Http)));
    }

    #[test]
    fn what_is_not_a_listening_socket_is_not_inherited() {
        let (stream, _) = std::os::unix::net::UnixStream::pair().unwrap();
        let unix = Inherited::identify(stream.into()).unwrap_err();
        assert!(
            unix.to_string().contains("not bound to an IP address"),
            "{unix}"
        );

        let unbound = socket2::Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        assert!(Inherited::identify(unbound.into()).is_err(), "no port");

        let file = tempfile::tempfile().unwrap();
        assert!(Inherited::identify(file.into()).is_err(), "not a socket");

        if cfg!(target_os = "linux") {
            let bound =
                socket2::Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
            bound.bind(&any.into()).unwrap();
            let idle = Inherited::identify(bound.into()).unwrap_err();
            assert!(idle.to_string().contains("does not listen"), "{idle}");
        }
    }

    #[test]
    fn an_adopted_listener_accepts_what_was_queued_before_it_changed_hands() {
        let first = bind("127.0.0.1:0".parse().unwrap(), ListenerKind::Http).unwrap();
        let handed = Inherited::identify(first.try_clone().unwrap()).unwrap();
        let addr = handed.addr;
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client.write_all(b"G").unwrap();
        drop(first);
        let fd = handed.adopt().unwrap();
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
            let (sock, remote) = listener.accept().await.unwrap();
            assert_eq!(remote, client.local_addr().unwrap());
            let fd = sock.fd();
            assert!(
                socket2::SockRef::from(&fd).tcp_nodelay().unwrap(),
                "TCP_NODELAY"
            );
        });
    }

    #[test]
    fn ipv6_wildcard_is_v6_only() {
        let fd = bind("[::]:0".parse().unwrap(), ListenerKind::Http).unwrap();
        assert!(socket2::SockRef::from(&fd).only_v6().unwrap());
    }
}
