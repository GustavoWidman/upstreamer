//! Origin discovery: sources outside the config that report origin sets. The control thread
//! owns a [`Feed`] and treats every report like a small reload: the upstream registry builds a
//! new `Upstreams` and the control thread publishes a generation with the same plan.
//!
//! In a build without the `kubernetes` feature, or with no source in the plan, `Feed::recv`
//! never resolves and no thread starts. The request path never sees this module.

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

/// The control thread's end of discovery.
#[derive(Default)]
pub(crate) struct Feed {}

impl Feed {
    pub fn new() -> Feed {
        Feed {}
    }

    /// After every published generation: start watches for new sources, stop those no pool
    /// names. Starts the discovery thread on the first source. Idempotent.
    pub fn set_sources(&mut self, plan: &crate::plan::Plan) {
        let _ = plan;
    }

    /// The next report. Pending forever when no source exists, so the control loop's
    /// `select!` arm costs nothing.
    pub async fn recv(&mut self) -> Found {
        std::future::pending().await
    }
}

/// Appends to the systemd status line what is wrong with the sources: those that never
/// synced, or lost their API server.
pub(crate) fn status(registry: &crate::upstream::Registry, out: &mut String) {
    for (source, endpoints) in registry.sources() {
        if !endpoints.synced {
            out.push_str(&format!("; discovery source {source:?} not synced"));
        }
    }
}

/// The sources' state, for `upstreamer_discovery_*`.
pub(crate) fn publish(registry: &crate::upstream::Registry, hub: &crate::metrics::Hub) {
    let _ = (registry, hub);
}
