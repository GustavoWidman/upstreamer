//! Per-core state for reaching origins: idle connections, resolved names, requests in flight
//! and failure counts per origin, per-pool balancing state, and TLS client configs. Accessed
//! only by tasks of its core, synchronously, so a `RefCell` borrow never spans an await.
//!
//! Idle connections sit in one LIFO stack per origin: the most recently used connection is the
//! warmest and the least likely to have been closed by the origin.
//!
//! Origins are indexed by the [`OriginId`]s of one `Upstreams` epoch. A request that started
//! under an older epoch still holds that epoch's ids, which may name other origins now, so
//! every access says which epoch its id is from and one from another epoch finds nothing here.
//! Each origin's counters sit behind an `Rc`, so a [`Busy`] guard that outlives an epoch change
//! still counts down the origin it counted up.

use super::conn::UpstreamConn;
use crate::plan::{OriginId, OriginKey, PoolId};
use crate::upstream::balance::PoolLocal;
use crate::upstream::{Epoch, Origin, Upstreams};
use smallvec::SmallVec;
use std::cell::{Cell, OnceCell, RefCell, RefMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a resolved origin name is used before it is resolved again.
const NAME_TTL: Duration = Duration::from_secs(30);

pub(crate) struct Pools {
    origins: RefCell<Origins>,
    /// By `PoolId` of the core's current plan: reset when the plan changes (a cursor
    /// restarting is harmless), kept across epochs of one plan.
    pools: RefCell<Vec<PoolLocal>>,
    /// Client configs with and without certificate verification, built on first use.
    tls: [OnceCell<Arc<rustls::ClientConfig>>; 2],
    /// The time of the last sweep. Idle ages are measured against it, so checking a
    /// connection in reads no clock; an age is at most one sweep interval short.
    now: Cell<Instant>,
}

#[derive(Default)]
struct Origins {
    /// The epoch whose ids index `slots`: that of the first table to use the pools, then of
    /// each table adopted.
    epoch: Option<Epoch>,
    slots: Vec<Slot>,
}

#[derive(Default)]
struct Slot {
    idle: Vec<UpstreamConn>,
    resolved: Option<Resolved>,
    local: Rc<OriginLocal>,
}

/// This core's counters of one origin.
#[derive(Debug, Default)]
pub(crate) struct OriginLocal {
    /// Checked-out connections of pool targets: requests in flight on this core.
    pub in_flight: Cell<u32>,
    /// Consecutive failed attempts on this core (passive health).
    pub fails: Cell<u8>,
}

/// Held by a checked-out connection of a pool target; counts it in flight until it is checked
/// in or dropped. `Target::Origin` connections carry none.
#[derive(Debug)]
pub(crate) struct Busy(Rc<OriginLocal>);

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.in_flight.set(self.0.in_flight.get() - 1);
    }
}

struct Resolved {
    addrs: SmallVec<[SocketAddr; 4]>,
    at: Instant,
}

impl Default for Pools {
    fn default() -> Self {
        Pools {
            origins: RefCell::default(),
            pools: RefCell::default(),
            tls: Default::default(),
            now: Cell::new(Instant::now()),
        }
    }
}

impl Pools {
    /// The slot of `id`, an origin of the table with `epoch`. `None` when the pools are
    /// indexed by another epoch.
    fn slot(&self, id: OriginId, epoch: Epoch) -> Option<RefMut<'_, Slot>> {
        let mut origins = self.origins.borrow_mut();
        if *origins.epoch.get_or_insert(epoch) != epoch {
            return None;
        }
        let index = id.0 as usize;
        if origins.slots.len() <= index {
            origins.slots.resize_with(index + 1, Slot::default);
        }
        Some(RefMut::map(origins, |o| &mut o.slots[index]))
    }

    /// Pops the newest idle connection to `id` on which the origin neither closed nor sent
    /// bytes meanwhile (read from the reactor's readiness, no syscall). Dead ones are closed
    /// on the way.
    pub fn checkout(&self, origin: &Origin, id: OriginId, epoch: Epoch) -> Option<UpstreamConn> {
        let _ = origin;
        let mut slot = self.slot(id, epoch)?;
        while let Some(conn) = slot.idle.pop() {
            if !conn.io.hung_up_or_readable() {
                return Some(conn);
            }
        }
        None
    }

    /// Keeps a connection whose last response was fully read and allowed reuse, unless it
    /// was dialled under another epoch than the pools are indexed by. Over the origin's
    /// `max_idle_per_core`, the oldest is closed. Drops the connection's busy guard.
    pub fn checkin(&self, mut conn: UpstreamConn, origin: &Origin) {
        conn.busy = None;
        let Some(mut slot) = self.slot(conn.origin, conn.epoch) else {
            return;
        };
        conn.idle_since = self.now.get();
        if slot.idle.len() >= usize::from(origin.spec.max_idle_per_core) {
            slot.idle.remove(0);
        }
        slot.idle.push(conn);
    }

    /// The guard a pool target's connection carries while checked out: counts one request in
    /// flight to `id` until dropped. `None` for another epoch.
    pub fn busy(&self, id: OriginId, epoch: Epoch) -> Option<Busy> {
        let slot = self.slot(id, epoch)?;
        slot.local.in_flight.set(slot.local.in_flight.get() + 1);
        Some(Busy(slot.local.clone()))
    }

    /// This core's counters of `id`; `None` for another epoch.
    pub fn local(&self, id: OriginId, epoch: Epoch) -> Option<Rc<OriginLocal>> {
        Some(self.slot(id, epoch)?.local.clone())
    }

    /// This core's state of a pool of the current plan.
    pub fn pool(&self, id: PoolId) -> RefMut<'_, PoolLocal> {
        let mut pools = self.pools.borrow_mut();
        let index = id.0 as usize;
        if pools.len() <= index {
            pools.resize_with(index + 1, PoolLocal::default);
        }
        RefMut::map(pools, |p| &mut p[index])
    }

    /// A new plan: pool ids name other pools now, so their state starts over.
    pub fn reset_pools(&self) {
        self.pools.borrow_mut().clear();
    }

    /// Closes connections idle past their origin's limit, and those the origin closed. Run by
    /// a core-local timer every few seconds, with the table the core serves.
    pub fn sweep(&self, upstreams: &Upstreams, now: Instant) {
        self.now.set(now);
        let mut origins = self.origins.borrow_mut();
        if origins.epoch != Some(upstreams.epoch) {
            return;
        }
        for (slot, origin) in origins.slots.iter_mut().zip(upstreams.origins()) {
            slot.idle.retain(|conn| {
                now.duration_since(conn.idle_since) < origin.spec.idle
                    && !conn.io.hung_up_or_readable()
            });
        }
    }

    /// On a new table: re-indexes by origin identity, keeping each staying origin's idle
    /// connections and counters and closing connections to origins that left. Resolved names
    /// are forgotten. Busy guards of an origin that left count down its dropped counters,
    /// which nothing reads any more.
    pub fn adopt(&self, old: &Upstreams, new: &Upstreams) {
        let mut origins = self.origins.borrow_mut();
        let indexed_by_old = origins.epoch == Some(old.epoch);
        let slots = std::mem::take(&mut origins.slots);
        origins.epoch = Some(new.epoch);
        origins
            .slots
            .resize_with(new.origins().len(), Slot::default);
        if !indexed_by_old {
            return;
        }
        let index: HashMap<OriginKey, usize> = new
            .origins()
            .iter()
            .enumerate()
            .map(|(i, o)| (o.spec.key(), i))
            .collect();
        for (slot, was) in slots.into_iter().zip(old.origins()) {
            let Some(&now) = index.get(&was.spec.key()) else {
                continue;
            };
            let kept = &mut origins.slots[now];
            kept.local = slot.local;
            kept.idle.extend(slot.idle.into_iter().map(|mut conn| {
                conn.origin = OriginId(now as u16);
                conn.epoch = new.epoch;
                conn
            }));
        }
    }

    /// The addresses `id`'s name resolved to, while they are fresh.
    pub fn resolved(&self, id: OriginId, epoch: Epoch) -> Option<SmallVec<[SocketAddr; 4]>> {
        let slot = self.slot(id, epoch)?;
        let resolved = slot.resolved.as_ref()?;
        (resolved.at.elapsed() < NAME_TTL).then(|| resolved.addrs.clone())
    }

    /// Remembers what `id`'s name resolved to (the address that took a connection first), or
    /// forgets it with `None` after none did.
    pub fn remember(&self, id: OriginId, epoch: Epoch, addrs: Option<SmallVec<[SocketAddr; 4]>>) {
        if let Some(mut slot) = self.slot(id, epoch) {
            slot.resolved = addrs.map(|addrs| Resolved {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Socket, Transport};
    use crate::plan::Plan;
    use crate::proxy::UpstreamIo;
    use crate::proxy::timer::Deadline;
    use crate::runtime::testing::plan_from;
    use crate::upstream::Registry;
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

    /// The table of `origins`, as one registry builds them in turn.
    fn table(registry: &mut Registry, origins: &[SocketAddr]) -> Arc<Upstreams> {
        registry.build(&plan(1, origins))
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
        /// A connection to this peer as origin `index` of `table`, and the peer's end of it.
        async fn connect(&self, table: &Upstreams, index: u16) -> (UpstreamConn, TcpStream) {
            let sock = Socket::connect(self.addr).await.unwrap();
            let (remote, _) = self.listener.accept().unwrap();
            let conn = UpstreamConn {
                io: UpstreamIo::Plain(Transport::Plain(sock)),
                buf: BytesMut::new(),
                origin: OriginId(index),
                epoch: table.epoch,
                busy: None,
                idle_since: Instant::now(),
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
            let up = table(&mut Registry::new(1), &[peer.addr]);
            let (origin, epoch) = (up.origin(OriginId(0)), up.epoch);
            let pools = Pools::default();
            assert!(pools.checkout(origin, OriginId(0), epoch).is_none());

            let mut remotes = Vec::new();
            let mut locals = Vec::new();
            for _ in 0..usize::from(origin.spec.max_idle_per_core) + 1 {
                let (conn, remote) = peer.connect(&up, 0).await;
                locals.push(conn.io_local_port());
                remotes.push(remote);
                pools.checkin(conn, origin);
            }
            let newest = pools.checkout(origin, OriginId(0), epoch).unwrap();
            assert_eq!(newest.io_local_port(), *locals.last().unwrap());
            let mut left = 1;
            let mut oldest_kept = newest.io_local_port();
            while let Some(conn) = pools.checkout(origin, OriginId(0), epoch) {
                left += 1;
                oldest_kept = conn.io_local_port();
            }
            assert_eq!(left, usize::from(origin.spec.max_idle_per_core));
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
            let up = table(&mut Registry::new(1), &[peer.addr]);
            let (origin, epoch) = (up.origin(OriginId(0)), up.epoch);
            let pools = Pools::default();
            let (quiet, _quiet_remote) = peer.connect(&up, 0).await;
            let quiet_port = quiet.io_local_port();
            let (closed, closed_remote) = peer.connect(&up, 0).await;
            let (chatty, mut chatty_remote) = peer.connect(&up, 0).await;
            pools.checkin(quiet, origin);
            pools.checkin(closed, origin);
            pools.checkin(chatty, origin);
            drop(closed_remote);
            std::io::Write::write_all(&mut chatty_remote, b"HTTP/1.1 408 Request Timeout\r\n\r\n")
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let conn = pools
                .checkout(origin, OriginId(0), epoch)
                .expect("the quiet connection");
            assert_eq!(conn.io_local_port(), quiet_port);
            assert!(
                pools.checkout(origin, OriginId(0), epoch).is_none(),
                "the other two were closed"
            );
        });
    }

    #[test]
    fn a_new_epoch_re_indexes_idle_connections_by_origin() {
        block_on(async {
            let (a, b, c) = (Peer::new(), Peer::new(), Peer::new());
            let mut registry = Registry::new(1);
            let old = table(&mut registry, &[a.addr, b.addr]);
            let new = table(&mut registry, &[c.addr, b.addr]);
            let pools = Pools::default();
            let (to_a, mut a_remote) = a.connect(&old, 0).await;
            let (to_b, _b_remote) = b.connect(&old, 1).await;
            pools.checkin(to_a, old.origin(OriginId(0)));
            pools.checkin(to_b, old.origin(OriginId(1)));

            pools.adopt(&old, &new);
            let mut end = [0u8; 1];
            assert_eq!(
                std::io::Read::read(&mut a_remote, &mut end).unwrap(),
                0,
                "the connection to the origin that left is closed"
            );
            assert!(
                pools
                    .checkout(new.origin(OriginId(0)), OriginId(0), new.epoch)
                    .is_none(),
                "the new first origin has no connection, whatever sat at index 0 before"
            );
            assert!(
                pools
                    .checkout(old.origin(OriginId(1)), OriginId(1), old.epoch)
                    .is_none(),
                "a request still running under the old epoch finds nothing by its ids"
            );
            let kept = pools
                .checkout(new.origin(OriginId(1)), OriginId(1), new.epoch)
                .expect("b's connection");
            assert_eq!(port(&kept), b.addr.port());
            assert_eq!((kept.origin, kept.epoch), (OriginId(1), new.epoch));

            let (stale, mut stale_remote) = a.connect(&old, 0).await;
            pools.checkin(stale, old.origin(OriginId(0)));
            assert_eq!(
                std::io::Read::read(&mut stale_remote, &mut end).unwrap(),
                0,
                "a connection dialled under the old epoch is closed, not pooled under its old id"
            );
            assert!(
                pools
                    .checkout(new.origin(OriginId(0)), OriginId(0), new.epoch)
                    .is_none()
            );
        });
    }

    #[test]
    fn a_busy_guard_across_an_epoch_counts_down_its_own_origin() {
        let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
            "10.0.0.1:80".parse().unwrap(),
            "10.0.0.2:80".parse().unwrap(),
            "10.0.0.3:80".parse().unwrap(),
        );
        let mut registry = Registry::new(1);
        let old = table(&mut registry, &[a, b]);
        let new = table(&mut registry, &[c, b]);
        let pools = Pools::default();
        let on_a = pools.busy(OriginId(0), old.epoch).unwrap();
        let on_b = pools.busy(OriginId(1), old.epoch).unwrap();
        let on_b_too = pools.busy(OriginId(1), old.epoch).unwrap();
        assert_eq!(
            pools.local(OriginId(1), old.epoch).unwrap().in_flight.get(),
            2
        );

        pools.adopt(&old, &new);
        assert!(
            pools.busy(OriginId(1), old.epoch).is_none(),
            "ids of the old epoch find nothing"
        );
        let b_now = pools.local(OriginId(1), new.epoch).unwrap();
        assert_eq!(
            b_now.in_flight.get(),
            2,
            "b's requests stay in flight at its new index"
        );
        assert_eq!(
            pools.local(OriginId(0), new.epoch).unwrap().in_flight.get(),
            0
        );
        drop(on_b);
        assert_eq!(b_now.in_flight.get(), 1);
        drop(on_a);
        assert_eq!(
            pools.local(OriginId(0), new.epoch).unwrap().in_flight.get(),
            0,
            "a's guard counts down a's dropped counters, not c's"
        );
        drop(on_b_too);
        assert_eq!(b_now.in_flight.get(), 0);
    }

    #[test]
    fn a_sweep_closes_connections_idle_past_the_origins_limit() {
        block_on(async {
            let peer = Peer::new();
            let up = table(&mut Registry::new(1), &[peer.addr]);
            let (origin, epoch) = (up.origin(OriginId(0)), up.epoch);
            let idle = origin.spec.idle;
            let pools = Pools::default();
            let start = Instant::now();
            pools.sweep(&up, start);
            let (conn, _remote) = peer.connect(&up, 0).await;
            pools.checkin(conn, origin);
            pools.sweep(&up, start + idle - Duration::from_secs(1));
            let conn = pools
                .checkout(origin, OriginId(0), epoch)
                .expect("still fresh");
            pools.checkin(conn, origin);
            pools.sweep(&up, start + 2 * idle);
            assert!(
                pools.checkout(origin, OriginId(0), epoch).is_none(),
                "closed by the sweep"
            );
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
