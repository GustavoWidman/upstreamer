//! Kubernetes EndpointSlice watches. Compiled only with `--features kubernetes`.
//!
//! Selection:
//! - `service = "web"`: EndpointSlices labelled `kubernetes.io/service-name=web`.
//! - `selector = "k=v,..."`: EndpointSlices matching the selector. The EndpointSlice
//!   controller copies a Service's labels onto its slices, so one watch covers every matching
//!   Service.
//!
//! Membership: the endpoints of the slices whose `conditions.ready` is true (absent means
//! ready, as the API defines it) and `terminating` is not, at the slice port that matches the
//! source's port (by name, or by number as the slice lists it, which is the pod's port), each
//! address once. Slices of address type `FQDN` are skipped: members are dialled by address.
//!
//! Protocol, per source: a `list` of the slices gives the state and a `resourceVersion`; a
//! `watch` from that version (with bookmarks, bounded by `timeoutSeconds`) keeps it current
//! and is started again from the last version seen when the server ends it. A `410 Gone`,
//! as the response or as an `ERROR` event, relists. Any other failure reports the source
//! unreachable (its last endpoints stay in use), waits with jittered exponential backoff, and
//! relists.
//!
//! Reports are coalesced: the first change after a report starts a window, and one report
//! with the set as it is at the window's end follows. The first list after start, and a
//! change of state, are reported at once.
//!
//! RBAC: get, list, watch on `endpointslices.discovery.k8s.io` in each namespace named;
//! nothing else (`docs/kubernetes-rbac.yaml`).

mod api;
mod config;
#[cfg(test)]
mod tests;

use super::{Found, SourceKey, SourceState};
use crate::plan::{KubePort, KubeSelect, KubeWatch};
use api::Failure;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Loads the cluster to talk to; called once per list cycle.
type Loader = Arc<dyn Fn() -> Result<config::Cluster, String> + Send + Sync>;

/// The delays of a watch, as values so tests can shrink them.
#[derive(Clone, Copy, Debug)]
pub(super) struct Timing {
    /// How long a change waits for others before it is reported.
    pub coalesce: Duration,
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    /// Bound on connecting, handshaking and receiving a response head.
    pub head: Duration,
    /// `timeoutSeconds` of a watch request: the server ends the stream after about this long.
    pub watch: Duration,
    /// How much longer than `watch` a silent stream is believed.
    pub grace: Duration,
    /// A stream that ends sooner than this without an event counts as a failure, so a server
    /// that closes every watch at once is not asked again in a tight loop.
    pub min_watch: Duration,
}

impl Default for Timing {
    fn default() -> Timing {
        Timing {
            coalesce: Duration::from_millis(250),
            backoff_start: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
            head: Duration::from_secs(30),
            watch: Duration::from_secs(300),
            grace: Duration::from_secs(30),
            min_watch: Duration::from_secs(1),
        }
    }
}

/// The discovery thread and its channels.
pub(super) struct Thread {
    commands: UnboundedSender<Vec<Arc<KubeWatch>>>,
    found: UnboundedReceiver<Found>,
}

impl Thread {
    pub fn spawn() -> std::io::Result<Thread> {
        Thread::spawn_with(Arc::new(config::infer), Timing::default())
    }

    fn spawn_with(load: Loader, timing: Timing) -> std::io::Result<Thread> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (commands, mut wanted) = unbounded_channel::<Vec<Arc<KubeWatch>>>();
        let (out, found) = unbounded_channel();
        std::thread::Builder::new()
            .name("upstreamer-discovery".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let mut running: HashMap<Arc<KubeWatch>, tokio::task::JoinHandle<()>> =
                        HashMap::new();
                    // Ends when the control thread drops its end.
                    while let Some(list) = wanted.recv().await {
                        running.retain(|key, task| {
                            let keep = list.contains(key);
                            if !keep {
                                task.abort();
                            }
                            keep
                        });
                        for key in list {
                            running.entry(key.clone()).or_insert_with(|| {
                                tokio::spawn(watch(key, load.clone(), timing, out.clone()))
                            });
                        }
                    }
                    for task in running.values() {
                        task.abort();
                    }
                });
            })?;
        Ok(Thread { commands, found })
    }

    /// The watches that should run; starts new ones and stops the rest.
    pub fn set_sources(&self, wanted: Vec<Arc<KubeWatch>>) {
        let _ = self.commands.send(wanted);
    }

    /// The next report; `None` once the thread is gone.
    pub async fn recv(&mut self) -> Option<Found> {
        self.found.recv().await
    }
}

/// One source's watch, forever: list, watch, and on failure report, back off and list again.
async fn watch(source: Arc<KubeWatch>, load: Loader, timing: Timing, out: UnboundedSender<Found>) {
    let mut run = Run {
        key: SourceKey::Kubernetes(source.clone()),
        source,
        timing,
        out,
        known: HashMap::new(),
        version: String::new(),
        reported: None,
        unreachable_since: None,
        dirty_since: None,
        events: 0,
        backoff: Backoff::new(timing),
    };
    run.send_unreachable("waiting for the first list".into());
    let mut gone_idle = false;
    loop {
        let events = run.events;
        match run.cycle(&load).await {
            Ok(never) => match never {},
            Err(Failure::Gone) if !gone_idle || run.events > events => {
                // The version expired: relist at once, once. A server that expires a fresh
                // version again is treated like any other failure.
                gone_idle = run.events == events;
                continue;
            }
            Err(failure) => {
                crate::log::warning!(
                    "discovery {}: {failure}; retrying, last endpoints stay in use",
                    run.key.label()
                );
                run.send_unreachable(failure.to_string());
                tokio::time::sleep(run.backoff.next()).await;
            }
        }
        gone_idle = false;
    }
}

struct Run {
    key: SourceKey,
    source: Arc<KubeWatch>,
    timing: Timing,
    out: UnboundedSender<Found>,
    /// Endpoints per slice name.
    known: HashMap<String, Vec<SocketAddr>>,
    version: String,
    /// The set the control thread last got.
    reported: Option<Arc<[SocketAddr]>>,
    unreachable_since: Option<SystemTime>,
    /// When the oldest change not yet reported happened.
    dirty_since: Option<Instant>,
    /// Watch events handled, for telling a relist that made progress from one that did not.
    events: u64,
    backoff: Backoff,
}

impl Run {
    /// A list, then watches until something fails.
    async fn cycle(&mut self, load: &Loader) -> Result<std::convert::Infallible, Failure> {
        let mut cluster = load()?;
        self.list(&mut cluster).await?;
        loop {
            self.watch_once(&mut cluster).await?;
        }
    }

    fn path(&self, query: &str) -> String {
        let selector = match &self.source.select {
            KubeSelect::Service(name) => format!("kubernetes.io/service-name={name}"),
            KubeSelect::Labels(selector) => selector.to_string(),
        };
        format!(
            "/apis/discovery.k8s.io/v1/namespaces/{}/endpointslices?labelSelector={}{query}",
            encode(&self.source.namespace),
            encode(&selector),
        )
    }

    async fn list(&mut self, cluster: &mut config::Cluster) -> Result<(), Failure> {
        let response = api::get(cluster, &self.path(""), self.timing.head).await?;
        let body = tokio::time::timeout(self.timing.head, response.read_to_end())
            .await
            .map_err(|_| Failure::Other("list timed out".into()))?
            .map_err(|e| Failure::Other(format!("list: {e}")))?;
        let list: List = serde_json::from_slice(&body)
            .map_err(|e| Failure::Other(format!("list: malformed answer: {e}")))?;
        let version = list
            .metadata
            .and_then(|m| m.resource_version)
            .ok_or_else(|| Failure::Other("list: answer has no resourceVersion".into()))?;
        self.known = list
            .items
            .iter()
            .map(|slice| {
                (
                    slice.metadata.name.clone(),
                    slice.endpoints_at(&self.source.port),
                )
            })
            .collect();
        self.version = version;
        self.dirty_since = None;
        self.send_synced();
        Ok(())
    }

    /// One watch request until the server ends it. `Ok` means it ended cleanly.
    async fn watch_once(&mut self, cluster: &mut config::Cluster) -> Result<(), Failure> {
        let started = Instant::now();
        let events_before = self.events;
        let query = format!(
            "&watch=true&allowWatchBookmarks=true&resourceVersion={}&timeoutSeconds={}",
            encode(&self.version),
            self.timing.watch.as_secs().max(1),
        );
        let mut response = api::get(cluster, &self.path(&query), self.timing.head).await?;
        let deadline = tokio::time::Instant::now() + self.timing.watch + self.timing.grace;
        loop {
            let window = self
                .dirty_since
                .map(|since| tokio::time::Instant::from_std(since + self.timing.coalesce));
            let line = tokio::select! {
                line = response.next_line() => line,
                () = sleep_until(window), if window.is_some() => {
                    self.send_synced();
                    continue;
                }
                () = tokio::time::sleep_until(deadline) => {
                    return Err(Failure::Other("watch went silent".into()));
                }
            };
            match line.map_err(|e| Failure::Other(format!("watch: {e}")))? {
                Some(line) if line.is_empty() => {}
                Some(line) => {
                    self.apply(&line)?;
                    self.events += 1;
                    self.backoff.reset();
                }
                None => {
                    if self.events == events_before && started.elapsed() < self.timing.min_watch {
                        return Err(Failure::Other("watch ended at once".into()));
                    }
                    self.backoff.reset();
                    return Ok(());
                }
            }
        }
    }

    fn apply(&mut self, line: &[u8]) -> Result<(), Failure> {
        let event: Event = serde_json::from_slice(line)
            .map_err(|e| Failure::Other(format!("watch: malformed event: {e}")))?;
        match event.kind.as_str() {
            "ADDED" | "MODIFIED" => {
                let slice: Slice = serde_json::from_value(event.object)
                    .map_err(|e| Failure::Other(format!("watch: malformed EndpointSlice: {e}")))?;
                self.note_version(slice.metadata.resource_version.as_deref());
                self.known.insert(
                    slice.metadata.name.clone(),
                    slice.endpoints_at(&self.source.port),
                );
                self.touch();
            }
            "DELETED" => {
                let meta: Meta = event
                    .object
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .ok_or_else(|| Failure::Other("watch: DELETED without metadata".into()))?;
                self.note_version(meta.resource_version.as_deref());
                self.known.remove(&meta.name);
                self.touch();
            }
            "BOOKMARK" => {
                let version = event
                    .object
                    .pointer("/metadata/resourceVersion")
                    .and_then(|v| v.as_str());
                self.note_version(version);
            }
            "ERROR" => {
                let code = event.object.get("code").and_then(|c| c.as_u64());
                if code == Some(410) {
                    return Err(Failure::Gone);
                }
                let message = event
                    .object
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("no message");
                return Err(Failure::Other(format!("watch: server error: {message}")));
            }
            _ => {}
        }
        Ok(())
    }

    fn note_version(&mut self, version: Option<&str>) {
        if let Some(version) = version.filter(|v| !v.is_empty()) {
            self.version = version.to_owned();
        }
    }

    fn endpoints(&self) -> Arc<[SocketAddr]> {
        let all: BTreeSet<SocketAddr> = self.known.values().flatten().copied().collect();
        all.into_iter().collect()
    }

    /// A slice changed: opens the coalescing window unless the set is what was reported.
    fn touch(&mut self) {
        if self.reported.as_deref() == Some(&*self.endpoints()) {
            self.dirty_since = None;
        } else {
            self.dirty_since.get_or_insert_with(Instant::now);
        }
    }

    /// Reports the current set as synced, unless the control thread already has it and
    /// believes the source synced.
    fn send_synced(&mut self) {
        let endpoints = self.endpoints();
        self.dirty_since = None;
        if self.unreachable_since.is_none() && self.reported.as_deref() == Some(&*endpoints) {
            return;
        }
        if self.unreachable_since.take().is_some() {
            crate::log::info!(
                "discovery {}: synced, {} endpoints",
                self.key.label(),
                endpoints.len()
            );
        }
        self.reported = Some(endpoints.clone());
        let _ = self.out.send(Found {
            source: self.key.clone(),
            endpoints,
            state: SourceState::Synced,
        });
    }

    /// Reports the source unreachable with the endpoints the control thread already has, once
    /// per outage.
    fn send_unreachable(&mut self, error: String) {
        if self.unreachable_since.is_some() {
            return;
        }
        let since = SystemTime::now();
        self.unreachable_since = Some(since);
        let endpoints = self.reported.get_or_insert_with(|| Arc::from([])).clone();
        let _ = self.out.send(Found {
            source: self.key.clone(),
            endpoints,
            state: SourceState::Unreachable {
                since,
                error: error.into(),
            },
        });
    }
}

async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Exponential delays with jitter: `start`, doubling to `max`, each drawn from the upper half
/// of its range so a fleet that lost its API server together does not return together.
struct Backoff {
    start: Duration,
    max: Duration,
    failures: u32,
}

impl Backoff {
    fn new(timing: Timing) -> Backoff {
        Backoff {
            start: timing.backoff_start,
            max: timing.backoff_max,
            failures: 0,
        }
    }

    fn next(&mut self) -> Duration {
        let delay = self.delay(unit_random());
        self.failures = self.failures.saturating_add(1);
        delay
    }

    /// The delay for the current failure count, `unit` in `[0, 1)` picking the jitter.
    fn delay(&self, unit: f64) -> Duration {
        let ceiling = self
            .start
            .saturating_mul(1u32.checked_shl(self.failures.min(30)).unwrap_or(u32::MAX))
            .min(self.max);
        ceiling.mul_f64(0.5 + 0.5 * unit)
    }

    fn reset(&mut self) {
        self.failures = 0;
    }
}

fn unit_random() -> f64 {
    let mut bytes = [0u8; 8];
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        return 0.5;
    }
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

/// Percent-encodes everything but RFC 3986's unreserved characters.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[derive(Deserialize)]
struct List {
    metadata: Option<ListMeta>,
    #[serde(default)]
    items: Vec<Slice>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListMeta {
    resource_version: Option<String>,
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "type")]
    kind: String,
    object: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    name: String,
    resource_version: Option<String>,
}

/// The parts of `discovery.k8s.io/v1` `EndpointSlice` that membership reads.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Slice {
    metadata: Meta,
    address_type: Option<String>,
    endpoints: Option<Vec<SliceEndpoint>>,
    ports: Option<Vec<SlicePort>>,
}

#[derive(Deserialize)]
struct SliceEndpoint {
    addresses: Option<Vec<String>>,
    conditions: Option<Conditions>,
}

#[derive(Deserialize)]
struct Conditions {
    ready: Option<bool>,
    terminating: Option<bool>,
}

#[derive(Deserialize)]
struct SlicePort {
    name: Option<String>,
    port: Option<u16>,
    protocol: Option<String>,
}

impl Slice {
    /// The ready, not terminating addresses at the ports that match `port`.
    fn endpoints_at(&self, port: &KubePort) -> Vec<SocketAddr> {
        if self.address_type.as_deref() == Some("FQDN") {
            return Vec::new();
        }
        let ports: Vec<u16> = self
            .ports
            .iter()
            .flatten()
            .filter(|p| p.protocol.as_deref().is_none_or(|p| p == "TCP"))
            .filter(|p| match port {
                KubePort::Number(n) => p.port == Some(*n),
                KubePort::Name(name) => p.name.as_deref() == Some(&**name),
            })
            .filter_map(|p| p.port)
            .collect();
        let mut out = Vec::new();
        for endpoint in self.endpoints.iter().flatten() {
            let conditions = endpoint.conditions.as_ref();
            // An absent `ready` means ready; `terminating` only excludes when true.
            let ready = conditions.and_then(|c| c.ready).unwrap_or(true);
            let terminating = conditions.and_then(|c| c.terminating).unwrap_or(false);
            if !ready || terminating {
                continue;
            }
            for address in endpoint.addresses.iter().flatten() {
                let Ok(ip) = address.parse::<IpAddr>() else {
                    continue;
                };
                out.extend(ports.iter().map(|&p| SocketAddr::new(ip, p)));
            }
        }
        out
    }
}
