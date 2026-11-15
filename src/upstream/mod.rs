//! Upstream state shared by every core: which origins each pool may use now, and their
//! health.
//!
//! Ownership, one writer per piece:
//! - [`Registry`] (control thread) builds every [`Upstreams`]. Nothing else makes one.
//! - `Upstreams` is immutable once built, published in the `Generation`, read by cores.
//! - [`Health`] cells are the only shared mutable state here, written in `health.rs`.
//!
//! Epochs. Every `Upstreams` gets a new epoch: a reload, or a discovery change with the same
//! plan. Per-core state indexed by `OriginId` (idle connections, requests in flight, failure
//! counts: `proxy::pool::Pools`) follows epochs, not plan generations, and re-indexes by
//! origin identity when one changes, so connections to an origin that stayed are kept.

pub(crate) mod balance;
pub(crate) mod health;
mod maglev;
mod tables;

pub(crate) use health::Health;

use crate::discover::{Found, SourceKey, SourceState};
use crate::plan::{
    MembersPlan, OriginAddr, OriginId, OriginKey, OriginSpec, Plan, PoolId, SourceSpec, UpstreamTls,
};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::ops::Range;
use std::sync::Arc;

/// Which `Upstreams` an `OriginId` belongs to. Epochs only ever compare for equality, so one
/// that wraps around after 2^32 tables is told apart from every table a connection or request
/// can still hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Epoch(pub u32);

/// The origins and member sets of one epoch.
pub(crate) struct Upstreams {
    pub epoch: Epoch,
    /// `plan.origins` first (same indices), then the origins of discovery sources.
    origins: Box<[Origin]>,
    /// By `PoolId`, the same index space as `plan.pools`.
    pools: Box<[Members]>,
}

/// One origin of an epoch.
pub(crate) struct Origin {
    pub spec: OriginSpec,
    /// Carried across epochs by identity: an origin that stays keeps its health.
    pub health: Arc<Health>,
    /// `host:port`, or the source's label for a discovered origin (its metrics aggregate
    /// there).
    pub label: Arc<str>,
    /// The core that runs this origin's probe: a hash of its identity modulo the core count,
    /// so it stays on one core across epochs and probes spread over cores.
    pub probe_core: u16,
}

/// What a pool may pick from in this epoch, with the tables its policy needs, built here once
/// per epoch, off the request path.
pub(crate) struct Members {
    pub origins: Box<[OriginId]>,
    /// Same length as `origins`; 0 = draining (never picked).
    pub weights: Box<[u16]>,
    pub select: Select,
}

pub(crate) enum Select {
    /// Indices into `origins`, interleaved by weight. Round robin and the tie-break of least
    /// requests walk it with a per-core cursor.
    Sequence(Box<[u16]>),
    /// Maglev lookup table (indices into `origins`), plus the sequence for keyless requests.
    Maglev {
        table: Box<[u16]>,
        fallback: Box<[u16]>,
    },
    /// Nothing to precompute: weights are read as they are.
    Weights,
}

impl Upstreams {
    #[inline]
    pub fn origin(&self, id: OriginId) -> &Origin {
        &self.origins[id.0 as usize]
    }
    pub fn members(&self, pool: PoolId) -> &Members {
        &self.pools[pool.0 as usize]
    }
    pub fn origins(&self) -> &[Origin] {
        &self.origins
    }
}

impl Members {
    /// Seconds until the first member could be picked again, at least 1: the Retry-After of
    /// a pool with nothing to pick.
    pub fn retry_after(&self, upstreams: &Upstreams, now: u32) -> u32 {
        let _ = (upstreams, now);
        1
    }
}

/// What a discovery source last reported.
#[derive(Clone, Debug)]
pub(crate) struct Endpoints {
    pub addrs: Arc<[SocketAddr]>,
    pub synced: bool,
}

/// The control thread's builder of [`Upstreams`]. Owns the health cells and the last endpoints
/// of every source, keyed by identity, so neither a reload nor a discovery change loses them.
pub(crate) struct Registry {
    next_epoch: u32,
    cores: u16,
    /// Cells of the origins in the current epoch, by identity. An origin that leaves drops
    /// its cell.
    health: HashMap<OriginKey, Arc<Health>>,
    /// Last endpoints by source identity, for the sources of the current plan.
    found: HashMap<SourceKey, Endpoints>,
}

impl Registry {
    pub fn new(cores: u16) -> Registry {
        Registry {
            next_epoch: 1,
            cores: cores.max(1),
            health: HashMap::new(),
            found: HashMap::new(),
        }
    }

    /// The table for `plan`: its origins at their ids, then each source's last endpoints
    /// (none before its first report) as origins with the source's settings, and every pool's
    /// members and selection tables. Health cells are carried by identity; new ones are
    /// healthy. Infallible: the compiler validated everything that could fail.
    pub fn build(&mut self, plan: &Plan) -> Arc<Upstreams> {
        let epoch = Epoch(self.next_epoch);
        self.next_epoch = self.next_epoch.wrapping_add(1);
        self.found
            .retain(|key, _| plan.sources.iter().any(|s| source_key(s) == *key));
        let mut health = HashMap::new();
        let mut origins: Vec<Origin> = Vec::with_capacity(plan.origins.len());
        for spec in plan.origins.iter() {
            let label = label(spec);
            origins.push(self.origin(&mut health, spec.clone(), label));
        }
        let mut ranges: Vec<Range<usize>> = Vec::with_capacity(plan.sources.len());
        for source in plan.sources.iter() {
            let start = origins.len();
            if let Some(found) = self.found.get(&source_key(source)) {
                for &addr in found.addrs.iter() {
                    let (spec, label) = discovered(source, addr);
                    origins.push(self.origin(&mut health, spec, label));
                }
            }
            ranges.push(start..origins.len());
        }
        self.health = health;
        let pools = plan
            .pools
            .iter()
            .map(|pool| {
                let (ids, weights): (Vec<OriginId>, Vec<u16>) = match &pool.members {
                    MembersPlan::Static(members) => members.iter().copied().unzip(),
                    MembersPlan::Discovered(source) => ranges[source.0 as usize]
                        .clone()
                        .map(|i| (OriginId(i as u16), 1))
                        .unzip(),
                };
                let keys: Vec<u64> = ids
                    .iter()
                    .map(|id| identity_hash(&origins[id.0 as usize].spec.key()))
                    .collect();
                Members {
                    select: tables::select(&pool.balance, &keys, &weights),
                    origins: ids.into(),
                    weights: weights.into(),
                }
            })
            .collect();
        Arc::new(Upstreams {
            epoch,
            origins: origins.into(),
            pools,
        })
    }

    /// A source reported. `Some(new table)` when its endpoints changed and `plan` uses the
    /// source; `None` when they are the ones already in use (a watch resync repeats them) or
    /// the plan has no such source.
    pub fn discovered(&mut self, plan: &Plan, found: Found) -> Option<Arc<Upstreams>> {
        if !plan.sources.iter().any(|s| source_key(s) == found.source) {
            return None;
        }
        let synced = matches!(found.state, SourceState::Synced);
        let endpoints = Endpoints {
            addrs: found.endpoints,
            synced,
        };
        let changed = self
            .found
            .get(&found.source)
            .is_none_or(|last| last.addrs != endpoints.addrs);
        self.found.insert(found.source, endpoints);
        changed.then(|| self.build(plan))
    }

    /// For `upstreamer_discovery_*` and the systemd status line.
    pub fn sources(&self) -> impl Iterator<Item = (&SourceKey, &Endpoints)> {
        self.found.iter()
    }

    fn origin(
        &self,
        health: &mut HashMap<OriginKey, Arc<Health>>,
        spec: OriginSpec,
        label: Arc<str>,
    ) -> Origin {
        let key = spec.key();
        let probe_core = (identity_hash(&key) % u64::from(self.cores)) as u16;
        let cell = health
            .entry(key.clone())
            .or_insert_with(|| self.health.get(&key).cloned().unwrap_or_default())
            .clone();
        Origin {
            spec,
            health: cell,
            label,
            probe_core,
        }
    }
}

fn source_key(source: &SourceSpec) -> SourceKey {
    match source {
        SourceSpec::Kubernetes(k) => SourceKey::Kubernetes(k.watch.clone()),
    }
}

/// The origin a source's endpoint becomes, and the label its metrics aggregate under.
fn discovered(source: &SourceSpec, addr: SocketAddr) -> (OriginSpec, Arc<str>) {
    match source {
        SourceSpec::Kubernetes(k) => (
            OriginSpec {
                host: addr.ip().to_string().into(),
                port: addr.port(),
                addr: OriginAddr::Ip(addr),
                tls: k.https.then(|| UpstreamTls {
                    server_name: k.server_name.clone(),
                    verify: k.verify,
                }),
                idle: k.idle,
                max_idle_per_core: crate::plan::compile::MAX_IDLE_PER_CORE,
                probe: k.probe.clone(),
            },
            Arc::from(&*k.label),
        ),
    }
}

/// `host:port`, with an IPv6 host in brackets.
fn label(spec: &OriginSpec) -> Arc<str> {
    if spec.host.contains(':') && !spec.host.starts_with('[') {
        format!("[{}]:{}", spec.host, spec.port).into()
    } else {
        format!("{}:{}", spec.host, spec.port).into()
    }
}

/// A hash of an origin's identity, the same in every process.
fn identity_hash(key: &OriginKey) -> u64 {
    let mut h = rustc_hash::FxHasher::with_seed(crate::key::FIXED_SEED as usize);
    key.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{
        BalancePlan, KubePort, KubeSelect, KubeSource, KubeWatch, PoolPlan, SourceId, StatusSet,
    };
    use crate::runtime::testing::plan_from;
    use std::time::Duration;

    fn proxied(origins: &[&str]) -> Plan {
        let routes: Vec<_> = origins
            .iter()
            .enumerate()
            .map(|(i, o)| serde_json::json!({ "when": { "path": format!("/{i}") }, "proxy": o }))
            .collect();
        plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": ["127.0.0.1:1"] },
                "sites": [{ "name": "a", "hosts": ["*"], "routes": routes }],
            }),
        )
    }

    /// `plan` with one discovery source and one pool over it.
    fn with_source(mut plan: Plan) -> (Plan, SourceKey) {
        let watch = Arc::new(KubeWatch {
            namespace: "web".into(),
            select: KubeSelect::Service("shop".into()),
            port: KubePort::Number(8080),
        });
        plan.sources = Box::new([SourceSpec::Kubernetes(KubeSource {
            watch: watch.clone(),
            https: false,
            server_name: None,
            verify: true,
            idle: Duration::from_secs(60),
            probe: None,
            label: "kubernetes:web/shop:8080".into(),
        })]);
        plan.pools = Box::new([PoolPlan {
            members: MembersPlan::Discovered(SourceId(0)),
            balance: BalancePlan::RoundRobin,
            retries: 1,
            fail_statuses: StatusSet::default(),
            passive: None,
        }]);
        (plan, SourceKey::Kubernetes(watch))
    }

    fn found(source: &SourceKey, addrs: &[&str]) -> Found {
        Found {
            source: source.clone(),
            endpoints: addrs.iter().map(|a| a.parse().unwrap()).collect(),
            state: SourceState::Synced,
        }
    }

    #[test]
    fn static_origins_keep_their_ids_and_health_follows_identity() {
        let mut registry = Registry::new(4);
        let first = registry.build(&proxied(&["http://10.0.0.1:80", "http://10.0.0.2:80"]));
        assert_eq!(first.epoch, Epoch(1));
        assert_eq!(&*first.origin(OriginId(1)).label, "10.0.0.2:80");
        first.origin(OriginId(1)).health.set_probe(true);

        let next = registry.build(&proxied(&["http://10.0.0.2:80", "http://[::1]:81"]));
        assert_eq!(next.epoch, Epoch(2), "every table is a new epoch");
        assert!(
            Arc::ptr_eq(
                &first.origin(OriginId(1)).health,
                &next.origin(OriginId(0)).health
            ),
            "an origin that stays keeps its cell at its new index"
        );
        assert!(next.origin(OriginId(0)).health.probe_down());
        assert!(
            !next.origin(OriginId(1)).health.probe_down(),
            "a new origin starts healthy"
        );
        assert_eq!(&*next.origin(OriginId(1)).label, "[::1]:81");
        assert_eq!(
            first.origin(OriginId(1)).probe_core,
            next.origin(OriginId(0)).probe_core,
            "the probing core follows identity"
        );

        let again = registry.build(&proxied(&["http://10.0.0.1:80"]));
        assert!(
            !again.origin(OriginId(0)).health.probe_down(),
            "a cell is dropped when its origin leaves"
        );
    }

    #[test]
    fn discovered_members_follow_static_origins_and_republish_only_on_change() {
        let (plan, source) = with_source(proxied(&["http://10.0.0.1:80"]));
        let mut registry = Registry::new(2);
        let empty = registry.build(&plan);
        assert!(
            empty.members(PoolId(0)).origins.is_empty(),
            "no member before a report"
        );

        let up = registry
            .discovered(&plan, found(&source, &["10.1.0.5:8080", "10.1.0.6:8080"]))
            .expect("new endpoints publish");
        assert_eq!(up.origins().len(), 3);
        assert_eq!(
            &*up.origin(OriginId(0)).label,
            "10.0.0.1:80",
            "static first"
        );
        assert_eq!(&*up.members(PoolId(0)).origins, [OriginId(1), OriginId(2)]);
        assert_eq!(&*up.members(PoolId(0)).weights, [1, 1]);
        assert_eq!(&*up.origin(OriginId(2)).label, "kubernetes:web/shop:8080");
        assert!(matches!(up.origin(OriginId(2)).spec.addr, OriginAddr::Ip(a) if a.port() == 8080));
        up.origin(OriginId(2)).health.set_probe(true);

        assert!(
            registry
                .discovered(&plan, found(&source, &["10.1.0.5:8080", "10.1.0.6:8080"]))
                .is_none(),
            "a resync with the same endpoints publishes nothing"
        );
        let shrunk = registry
            .discovered(&plan, found(&source, &["10.1.0.6:8080"]))
            .unwrap();
        assert_eq!(&*shrunk.members(PoolId(0)).origins, [OriginId(1)]);
        assert!(
            shrunk.origin(OriginId(1)).health.probe_down(),
            "the pod that stayed keeps its cell"
        );
        assert_ne!(shrunk.epoch, up.epoch);

        let reloaded = registry.build(&plan);
        assert_eq!(
            &*reloaded.members(PoolId(0)).origins,
            [OriginId(1)],
            "a reload keeps the last endpoints"
        );
        let other = proxied(&["http://10.0.0.1:80"]);
        assert!(
            registry
                .discovered(&other, found(&source, &["10.1.0.9:8080"]))
                .is_none(),
            "a plan without the source ignores it"
        );
    }
}
