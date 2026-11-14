//! Per-core state for reaching origins: idle connections, resolved names and TLS client
//! configs. Accessed only by tasks of its core, synchronously, so a `RefCell` borrow never
//! spans an await.
//!
//! Idle connections sit in one LIFO stack per origin: the most recently used connection is the
//! warmest and the least likely to have been closed by the origin.
//!
//! Origins are indexed by the [`UpstreamId`]s of one plan. A request that started under an
//! older plan still holds that plan's ids, which may name other origins now, so every access
//! says which plan its id is from and one from another plan finds nothing here.

use super::conn::UpstreamConn;
use crate::plan::{Plan, UpstreamPlan};
use smallvec::SmallVec;
use std::cell::{Cell, OnceCell, RefCell, RefMut};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a resolved origin name is used before it is resolved again.
const NAME_TTL: Duration = Duration::from_secs(30);

pub(crate) struct Pools {
    origins: RefCell<Origins>,
    /// Client configs with and without certificate verification, built on first use.
    tls: [OnceCell<Arc<rustls::ClientConfig>>; 2],
    /// The time of the last sweep. Idle ages are measured against it, so checking a
    /// connection in reads no clock; an age is at most one sweep interval short.
    now: Cell<Instant>,
}

#[derive(Default)]
struct Origins {
    /// Generation of the plan whose ids index `slots`: that of the first plan to use the
    /// pools, then of each plan adopted.
    generation: Option<u64>,
    slots: Vec<Origin>,
}

#[derive(Default)]
struct Origin {
    idle: Vec<UpstreamConn>,
    resolved: Option<Resolved>,
}

struct Resolved {
    addrs: SmallVec<[SocketAddr; 4]>,
    at: Instant,
}

impl Default for Pools {
    fn default() -> Self {
        Pools {
            origins: RefCell::default(),
            tls: Default::default(),
            now: Cell::new(Instant::now()),
        }
    }
}

impl Pools {
    /// The slot of `up`, an origin of the plan with `generation`. `None` when the pools are
    /// indexed by another plan.
    fn origin(&self, up: &UpstreamPlan, generation: u64) -> Option<RefMut<'_, Origin>> {
        let mut origins = self.origins.borrow_mut();
        if *origins.generation.get_or_insert(generation) != generation {
            return None;
        }
        let index = up.id.0 as usize;
        if origins.slots.len() <= index {
            origins.slots.resize_with(index + 1, Origin::default);
        }
        Some(RefMut::map(origins, |o| &mut o.slots[index]))
    }

    /// Pops the newest idle connection to `up` on which the origin neither closed nor sent
    /// bytes meanwhile (read from the reactor's readiness, no syscall). Dead ones are closed
    /// on the way.
    pub fn checkout(&self, up: &UpstreamPlan, generation: u64) -> Option<UpstreamConn> {
        let mut origin = self.origin(up, generation)?;
        while let Some(conn) = origin.idle.pop() {
            if !conn.io.hung_up_or_readable() {
                return Some(conn);
            }
        }
        None
    }

    /// Keeps a connection whose last response was fully read and allowed reuse, unless it
    /// was dialled under another plan than the pools are indexed by. Over the origin's
    /// `max_idle_per_core`, the oldest is closed.
    pub fn checkin(&self, mut conn: UpstreamConn, up: &UpstreamPlan) {
        let Some(mut origin) = self.origin(up, conn.generation) else {
            return;
        };
        conn.idle_since = self.now.get();
        if origin.idle.len() >= usize::from(up.max_idle_per_core) {
            origin.idle.remove(0);
        }
        origin.idle.push(conn);
    }

    /// Closes connections idle past their origin's limit, and those the origin closed. Run by
    /// a core-local timer every few seconds, with the plan the core serves.
    pub fn sweep(&self, plan: &Plan, now: Instant) {
        self.now.set(now);
        let mut origins = self.origins.borrow_mut();
        if origins.generation != Some(plan.generation) {
            return;
        }
        for (origin, up) in origins.slots.iter_mut().zip(plan.upstreams.iter()) {
            origin.idle.retain(|conn| {
                now.duration_since(conn.idle_since) < up.idle && !conn.io.hung_up_or_readable()
            });
        }
    }

    /// On a new plan: re-indexes by the new origin ids, closing connections to origins that
    /// are gone or whose address or TLS settings changed. Resolved names are forgotten.
    pub fn adopt(&self, old: &Plan, new: &Plan) {
        let mut origins = self.origins.borrow_mut();
        let indexed_by_old = origins.generation == Some(old.generation);
        let slots = std::mem::take(&mut origins.slots);
        origins.generation = Some(new.generation);
        origins
            .slots
            .resize_with(new.upstreams.len(), Origin::default);
        if !indexed_by_old {
            return;
        }
        for (slot, was) in slots.into_iter().zip(old.upstreams.iter()) {
            let Some(now) = new.upstreams.iter().find(|u| same_origin(was, u)) else {
                continue;
            };
            let idle = slot.idle.into_iter().map(|mut conn| {
                conn.upstream = now.id;
                conn.generation = new.generation;
                conn
            });
            origins.slots[now.id.0 as usize].idle.extend(idle);
        }
    }

    /// The addresses `up`'s name resolved to, while they are fresh.
    pub fn resolved(
        &self,
        up: &UpstreamPlan,
        generation: u64,
    ) -> Option<SmallVec<[SocketAddr; 4]>> {
        let origin = self.origin(up, generation)?;
        let resolved = origin.resolved.as_ref()?;
        (resolved.at.elapsed() < NAME_TTL).then(|| resolved.addrs.clone())
    }

    /// Remembers what `up`'s name resolved to (the address that took a connection first), or
    /// forgets it with `None` after none did.
    pub fn remember(
        &self,
        up: &UpstreamPlan,
        generation: u64,
        addrs: Option<SmallVec<[SocketAddr; 4]>>,
    ) {
        if let Some(mut origin) = self.origin(up, generation) {
            origin.resolved = addrs.map(|addrs| Resolved {
                addrs,
                at: Instant::now(),
            });
        }
    }

    /// This core's TLS client config. Sessions are cached in it, so a redial resumes.
    pub fn client_tls(&self, verify: bool) -> Arc<rustls::ClientConfig> {
        self.tls[usize::from(verify)]
            .get_or_init(|| {
                let mut config = (*crate::tls::client_config(verify)).clone();
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
                Arc::new(config)
            })
            .clone()
    }
}

fn same_origin(a: &UpstreamPlan, b: &UpstreamPlan) -> bool {
    let tls = |u: &UpstreamPlan| u.tls.as_ref().map(|t| (t.server_name.clone(), t.verify));
    a.host == b.host && a.port == b.port && tls(a) == tls(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Socket, Transport};
    use crate::proxy::UpstreamIo;
    use crate::proxy::timer::Deadline;
    use crate::runtime::testing::plan_from;
    use bytes::BytesMut;
    use std::net::{TcpListener, TcpStream};

    /// A plan that proxies `/0`, `/1`, ... to `origins`, in that order.
    fn plan(generation: u64, origins: &[SocketAddr]) -> Plan {
        let routes: Vec<_> = origins
            .iter()
            .enumerate()
            .map(|(i, origin)| {
                serde_json::json!({
                    "when": { "path": format!("/{i}") },
                    "proxy": { "to": format!("http://{origin}"), "timeouts": { "idle": "30s" } },
                })
            })
            .collect();
        plan_from(
            generation,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": ["127.0.0.1:1"], "https": [] },
                "sites": [{ "name": "pools", "hosts": ["*"], "routes": routes }],
            }),
        )
    }

    struct Peer {
        listener: TcpListener,
        addr: SocketAddr,
    }

    impl Peer {
        fn new() -> Peer {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            Peer { listener, addr }
        }
        /// A connection to this peer as `plan`'s upstream `index`, and the peer's end of it.
        async fn connect(&self, plan: &Plan, index: usize) -> (UpstreamConn, TcpStream) {
            let sock = Socket::connect(self.addr).await.unwrap();
            let (remote, _) = self.listener.accept().unwrap();
            let conn = UpstreamConn {
                io: UpstreamIo::Plain(Transport::Plain(sock)),
                buf: BytesMut::new(),
                upstream: plan.upstreams[index].id,
                generation: plan.generation,
                idle_since: Instant::now(),
                requests: 1,
                watch: Deadline::default(),
            };
            (conn, remote)
        }
    }

    fn block_on<T>(test: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(test)
    }

    fn port(conn: &UpstreamConn) -> u16 {
        let UpstreamIo::Plain(io) = &conn.io else {
            panic!("a cleartext connection");
        };
        let fd = io.socket().fd();
        socket2::SockRef::from(&fd)
            .peer_addr()
            .unwrap()
            .as_socket()
            .unwrap()
            .port()
    }

    #[test]
    fn the_newest_idle_connection_is_used_first_and_the_oldest_dropped_over_the_cap() {
        block_on(async {
            let peer = Peer::new();
            let plan = plan(1, &[peer.addr]);
            let up = &plan.upstreams[0];
            let pools = Pools::default();
            assert!(pools.checkout(up, 1).is_none());

            let mut remotes = Vec::new();
            let mut locals = Vec::new();
            for _ in 0..usize::from(up.max_idle_per_core) + 1 {
                let (conn, remote) = peer.connect(&plan, 0).await;
                locals.push(conn.io_local_port());
                remotes.push(remote);
                pools.checkin(conn, up);
            }
            let newest = pools.checkout(up, 1).unwrap();
            assert_eq!(newest.io_local_port(), *locals.last().unwrap());
            let mut left = 1;
            let mut oldest_kept = newest.io_local_port();
            while let Some(conn) = pools.checkout(up, 1) {
                left += 1;
                oldest_kept = conn.io_local_port();
            }
            assert_eq!(left, usize::from(up.max_idle_per_core));
            assert_eq!(
                oldest_kept, locals[1],
                "the first one checked in was closed"
            );
        });
    }

    #[test]
    fn a_connection_the_origin_closed_or_wrote_on_is_not_handed_out() {
        block_on(async {
            let peer = Peer::new();
            let plan = plan(1, &[peer.addr]);
            let up = &plan.upstreams[0];
            let pools = Pools::default();
            let (quiet, _quiet_remote) = peer.connect(&plan, 0).await;
            let quiet_port = quiet.io_local_port();
            let (closed, closed_remote) = peer.connect(&plan, 0).await;
            let (chatty, mut chatty_remote) = peer.connect(&plan, 0).await;
            pools.checkin(quiet, up);
            pools.checkin(closed, up);
            pools.checkin(chatty, up);
            drop(closed_remote);
            std::io::Write::write_all(&mut chatty_remote, b"HTTP/1.1 408 Request Timeout\r\n\r\n")
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let conn = pools.checkout(up, 1).expect("the quiet connection");
            assert_eq!(conn.io_local_port(), quiet_port);
            assert!(pools.checkout(up, 1).is_none(), "the other two were closed");
        });
    }

    #[test]
    fn a_new_plan_re_indexes_idle_connections_by_origin() {
        block_on(async {
            let (a, b, c) = (Peer::new(), Peer::new(), Peer::new());
            let old = plan(1, &[a.addr, b.addr]);
            let new = plan(2, &[c.addr, b.addr]);
            let pools = Pools::default();
            let (to_a, mut a_remote) = a.connect(&old, 0).await;
            let (to_b, _b_remote) = b.connect(&old, 1).await;
            pools.checkin(to_a, &old.upstreams[0]);
            pools.checkin(to_b, &old.upstreams[1]);

            pools.adopt(&old, &new);
            let mut end = [0u8; 1];
            assert_eq!(
                std::io::Read::read(&mut a_remote, &mut end).unwrap(),
                0,
                "the connection to the origin that left is closed"
            );
            assert!(
                pools.checkout(&new.upstreams[0], 2).is_none(),
                "the new first origin has no connection, whatever sat at index 0 before"
            );
            assert!(
                pools.checkout(&old.upstreams[1], 1).is_none(),
                "a request still running under the old plan finds nothing by its ids"
            );
            let kept = pools
                .checkout(&new.upstreams[1], 2)
                .expect("b's connection");
            assert_eq!(port(&kept), b.addr.port());
            assert_eq!((kept.upstream, kept.generation), (new.upstreams[1].id, 2));

            let (stale, mut stale_remote) = a.connect(&old, 0).await;
            pools.checkin(stale, &old.upstreams[0]);
            assert_eq!(
                std::io::Read::read(&mut stale_remote, &mut end).unwrap(),
                0,
                "a connection dialled under the old plan is closed, not pooled under its old id"
            );
            assert!(pools.checkout(&new.upstreams[0], 2).is_none());
        });
    }

    #[test]
    fn a_sweep_closes_connections_idle_past_the_origins_limit() {
        block_on(async {
            let peer = Peer::new();
            let plan = plan(1, &[peer.addr]);
            let up = &plan.upstreams[0];
            let pools = Pools::default();
            let start = Instant::now();
            pools.sweep(&plan, start);
            let (conn, _remote) = peer.connect(&plan, 0).await;
            pools.checkin(conn, up);
            pools.sweep(&plan, start + up.idle - Duration::from_secs(1));
            let conn = pools.checkout(up, 1).expect("still fresh");
            pools.checkin(conn, up);
            pools.sweep(&plan, start + 2 * up.idle);
            assert!(pools.checkout(up, 1).is_none(), "closed by the sweep");
        });
    }

    impl UpstreamConn {
        fn io_local_port(&self) -> u16 {
            let UpstreamIo::Plain(io) = &self.io else {
                panic!("a cleartext connection");
            };
            let fd = io.socket().fd();
            socket2::SockRef::from(&fd)
                .local_addr()
                .unwrap()
                .as_socket()
                .unwrap()
                .port()
        }
    }
}
