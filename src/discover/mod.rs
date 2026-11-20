//! Origin discovery: sources outside the config that report origin sets. The control thread
//! owns a [`Feed`] and treats every report like a small reload: the upstream registry builds a
//! new `Upstreams` and the control thread publishes a generation with the same plan.
//!
//! In a build without the `kubernetes` feature, or with no source in the plan, `Feed::recv`
//! never resolves and no thread starts. The request path never sees this module.

#[cfg(feature = "kubernetes")]
mod kube;

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

/// Appends to the systemd status line what is wrong with the sources: those that never
/// synced, or lost their API server.
pub(crate) fn status(registry: &crate::upstream::Registry, out: &mut String) {
    let mut unsynced: Vec<String> = registry
        .sources()
        .filter(|(_, endpoints)| !endpoints.synced)
        .map(|(source, _)| source.label())
        .collect();
    unsynced.sort();
    for label in unsynced {
        out.push_str("; discovery source ");
        out.push_str(&label);
        out.push_str(" is not synced");
    }
}

/// The sources' state, for `upstreamer_discovery_*`.
pub(crate) fn publish(registry: &crate::upstream::Registry, hub: &crate::metrics::Hub) {
    let mut sources: Vec<(Arc<str>, usize, bool)> = registry
        .sources()
        .map(|(source, endpoints)| {
            (
                Arc::from(source.label()),
                endpoints.addrs.len(),
                endpoints.synced,
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

    #[tokio::test]
    async fn a_feed_without_sources_never_reports() {
        let mut feed = Feed::new();
        let waited = tokio::time::timeout(std::time::Duration::from_millis(50), feed.recv()).await;
        assert!(waited.is_err());
    }
}
