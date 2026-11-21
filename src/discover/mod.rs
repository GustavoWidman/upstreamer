//! Origin discovery: sources outside the config that report origin sets. The control thread
//! owns a [`Feed`] and treats every report like a small reload: the upstream registry builds a
//! new `Upstreams` and the control thread publishes a generation with the same plan.
//!
//! In a build without the `kubernetes` feature, or with no source in the plan, `Feed::recv`
//! never resolves and no thread starts. The request path never sees this module.

#[cfg(feature = "kubernetes")]
mod kube;
#[cfg(all(feature = "kubernetes", feature = "internals"))]
pub use kube::harness as kube_harness;

use std::net::SocketAddr;
use std::sync::Arc;

/// A source's identity across reloads: what its watch observes (namespace, selection, port).
/// Two plans naming the same watch share it and its last endpoints, whatever scheme, TLS
/// name, idle timeout or probe their origins get.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum SourceKey {
    Kubernetes(Arc<crate::plan::KubeWatch>),
}

/// A source's report.
#[derive(Debug)]
pub(crate) struct Found {
    pub source: SourceKey,
    /// Ready, not terminating endpoints at the source's port; sorted and deduplicated, so
    /// equal sets compare equal.
    pub endpoints: Arc<[SocketAddr]>,
    pub state: SourceState,
}

#[derive(Debug, Clone)]
pub(crate) enum SourceState {
    Synced,
    /// Endpoints are the last known ones.
    Unreachable {
        since: std::time::SystemTime,
        error: Arc<str>,
    },
}

impl SourceKey {
    /// What the source's origins are called in metrics and the status line:
    /// `kubernetes:<namespace>/<service or selector>:<port>`.
    pub fn label(&self) -> String {
        use crate::plan::{KubePort, KubeSelect};
        match self {
            SourceKey::Kubernetes(watch) => {
                let select = match &watch.select {
                    KubeSelect::Service(name) => name,
                    KubeSelect::Labels(selector) => selector,
                };
                match &watch.port {
                    KubePort::Number(n) => format!("kubernetes:{}/{select}:{n}", watch.namespace),
                    KubePort::Name(n) => format!("kubernetes:{}/{select}:{n}", watch.namespace),
                }
            }
        }
    }
}

/// The control thread's end of discovery.
#[derive(Default)]
pub(crate) struct Feed {
    #[cfg(feature = "kubernetes")]
    thread: Option<kube::Thread>,
}

impl Feed {
    pub fn new() -> Feed {
        Feed::default()
    }

    /// After every published generation: start watches for new sources, stop those no pool
    /// names. Starts the discovery thread on the first source. Idempotent.
    pub fn set_sources(&mut self, plan: &crate::plan::Plan) {
        #[cfg(feature = "kubernetes")]
        {
            let wanted: Vec<_> = plan
                .sources
                .iter()
                .map(|source| match source {
                    crate::plan::SourceSpec::Kubernetes(k) => k.watch.clone(),
                })
                .collect();
            if self.thread.is_none() && !wanted.is_empty() {
                match kube::Thread::spawn() {
                    Ok(thread) => self.thread = Some(thread),
                    Err(e) => {
                        crate::log::error!("starting the discovery thread: {e}");
                        return;
                    }
                }
            }
            if let Some(thread) = &self.thread {
                thread.set_sources(wanted);
            }
        }
        #[cfg(not(feature = "kubernetes"))]
        let _ = plan;
    }

    /// The next report. Pending forever when no source exists, so the control loop's
    /// `select!` arm costs nothing.
    pub async fn recv(&mut self) -> Found {
        #[cfg(feature = "kubernetes")]
        if let Some(thread) = &mut self.thread
            && let Some(found) = thread.recv().await
        {
            return found;
        }
        std::future::pending().await
    }
}

/// Appends to the systemd status line what is wrong with the sources: those that have not
/// reported yet, and those that lost their API server, with the error and since when.
pub(crate) fn status(registry: &crate::upstream::Registry, out: &mut String) {
    use std::fmt::Write;
    let mut wrong: Vec<(String, &Option<SourceState>)> = registry
        .sources()
        .filter(|(_, endpoints)| !endpoints.synced())
        .map(|(source, endpoints)| (source.label(), &endpoints.state))
        .collect();
    wrong.sort_by(|a, b| a.0.cmp(&b.0));
    for (label, state) in wrong {
        let _ = match state {
            Some(SourceState::Unreachable { since, error }) => write!(
                out,
                "; discovery source {label} unreachable since {}: {error}",
                utc(*since)
            ),
            _ => write!(out, "; discovery source {label} has not synced yet"),
        };
    }
}

/// `2026-03-01T12:00:05Z`.
fn utc(at: std::time::SystemTime) -> String {
    let secs = at
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (year, month, day) = crate::runtime::civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

/// The sources' state, for `upstreamer_discovery_*`.
pub(crate) fn publish(registry: &crate::upstream::Registry, hub: &crate::metrics::Hub) {
    let mut sources: Vec<(Arc<str>, usize, bool)> = registry
        .sources()
        .map(|(source, endpoints)| {
            (
                Arc::from(source.label()),
                endpoints.addrs.len(),
                endpoints.synced(),
            )
        })
        .collect();
    sources.sort();
    hub.control().sources = sources;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{KubePort, KubeSelect, KubeWatch};

    fn key(select: KubeSelect, port: KubePort) -> SourceKey {
        SourceKey::Kubernetes(Arc::new(KubeWatch {
            namespace: "shop".into(),
            select,
            port,
        }))
    }

    #[test]
    fn labels_follow_the_documented_format() {
        assert_eq!(
            key(
                KubeSelect::Service("web".into()),
                KubePort::Name("http".into())
            )
            .label(),
            "kubernetes:shop/web:http"
        );
        assert_eq!(
            key(KubeSelect::Labels("app=web".into()), KubePort::Number(8080)).label(),
            "kubernetes:shop/app=web:8080"
        );
    }

    #[cfg(feature = "kubernetes")]
    /// A plan whose one pool is fed by the source `shop/web:8080`.
    fn plan_with_source() -> crate::plan::Plan {
        crate::runtime::testing::plan_from(
            1,
            &serde_json::json!({
                "version": 1,
                "listen": { "http": ["127.0.0.1:1"] },
                "sites": [{ "name": "a", "hosts": ["*"], "routes": [{ "proxy": { "to": {
                    "kubernetes": { "namespace": "shop", "service": "web", "port": 8080 },
                } } }] }],
            }),
        )
    }

    #[cfg(feature = "kubernetes")]
    fn status_of(registry: &crate::upstream::Registry) -> String {
        let mut out = String::new();
        status(registry, &mut out);
        out
    }

    #[cfg(feature = "kubernetes")]
    #[test]
    fn the_status_line_says_why_and_since_when_a_source_is_unreachable() {
        let plan = plan_with_source();
        let source = key(KubeSelect::Service("web".into()), KubePort::Number(8080));
        let mut registry = crate::upstream::Registry::new(1);
        registry.build(&plan);
        assert_eq!(
            status_of(&registry),
            "; discovery source kubernetes:shop/web:8080 has not synced yet"
        );
        let report = |state| Found {
            source: source.clone(),
            endpoints: Arc::from(["10.1.0.5:8080".parse().unwrap()]),
            state,
        };
        registry.discovered(&plan, report(SourceState::Synced));
        assert_eq!(status_of(&registry), "", "a synced source is not news");
        let since = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_772_366_405);
        registry.discovered(
            &plan,
            report(SourceState::Unreachable {
                since,
                error: "HTTP 503 etcd is down".into(),
            }),
        );
        assert_eq!(
            status_of(&registry),
            "; discovery source kubernetes:shop/web:8080 unreachable since \
             2026-03-01T12:00:05Z: HTTP 503 etcd is down"
        );
    }

    #[cfg(feature = "kubernetes")]
    #[test]
    fn every_source_of_the_plan_has_discovery_samples_from_the_start() {
        let plan = plan_with_source();
        let mut registry = crate::upstream::Registry::new(1);
        registry.build(&plan);
        let hub = crate::metrics::Hub::new(1);
        publish(&registry, &hub);
        assert_eq!(
            hub.control().sources,
            [(Arc::from("kubernetes:shop/web:8080"), 0, false)],
            "a source that has not reported is there, empty and not synced"
        );
        let source = key(KubeSelect::Service("web".into()), KubePort::Number(8080));
        let endpoints: Arc<[SocketAddr]> = Arc::from([
            "10.1.0.5:8080".parse().unwrap(),
            "10.1.0.6:8080".parse().unwrap(),
        ]);
        registry.discovered(
            &plan,
            Found {
                source,
                endpoints,
                state: SourceState::Synced,
            },
        );
        publish(&registry, &hub);
        assert_eq!(
            hub.control().sources,
            [(Arc::from("kubernetes:shop/web:8080"), 2, true)]
        );
    }

    #[tokio::test]
    async fn a_feed_without_sources_never_reports() {
        let mut feed = Feed::new();
        let waited = tokio::time::timeout(std::time::Duration::from_millis(50), feed.recv()).await;
        assert!(waited.is_err());
    }
}
