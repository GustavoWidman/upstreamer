use crate::state::AppState;
use anyhow::Result;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Service;
use kube::{Api, Client};
use kube_runtime::{watcher, WatchStreamExt};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};
use url::Url;

const POOL_ANNOTATION: &str = "upstreamer.ora.ooo/pool";
const PORT_ANNOTATION: &str = "upstreamer.ora.ooo/port";

fn service_to_origin(svc: &Service) -> Option<(String, Url)> {
    let name = svc.metadata.name.as_deref()?;
    let spec = svc.spec.as_ref()?;
    let cluster_ip = spec.cluster_ip.as_deref()?;
    let annotations = svc.metadata.annotations.as_ref();

    // Prefer annotated port, then first port in spec
    let port_str = annotations
        .and_then(|a| a.get(PORT_ANNOTATION))
        .cloned()
        .or_else(|| {
            spec.ports
                .as_ref()
                .and_then(|ports| ports.first())
                .map(|p| p.port.to_string())
        })?;

    let port: u16 = port_str.parse().ok()?;
    let url = Url::parse(&format!("http://{}:{}", cluster_ip, port)).ok()?;

    // Pool name from annotation, fallback to service name
    let pool = annotations
        .and_then(|a| a.get(POOL_ANNOTATION))
        .cloned()
        .unwrap_or_else(|| name.to_string());

    Some((pool, url))
}

async fn rebuild_router(state: &AppState, k8s_origins: &HashMap<String, Vec<Url>>) {
    let config = state.config.load();
    let router = crate::route::Router::from_config_with_k8s(&config, k8s_origins);
    state.router.swap(Arc::new(router));

    // Add origin states for any new k8s origins
    for origins in k8s_origins.values() {
        for url in origins {
            state
                .origin_states
                .entry(url.to_string())
                .or_insert_with(crate::balance::OriginState::new);
        }
    }
}

pub async fn run_k8s_discovery(state: Arc<AppState>) -> Result<()> {
    let k8s_config = match &state.config.load().kubernetes {
        Some(c) => c.clone(),
        None => return Ok(()),
    };

    info!(
        "Starting k8s Service discovery: namespace={:?}, label_selector={:?}",
        k8s_config.namespace, k8s_config.label_selector
    );

    let client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create k8s client (not in cluster?): {}", e);
            return Err(e.into());
        }
    };

    let services: Api<Service> = match &k8s_config.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client),
    };

    let wc = watcher::Config::default();
    let wc = match &k8s_config.label_selector {
        Some(ls) => wc.labels(ls),
        None => wc,
    };

    let mut k8s_origins: HashMap<String, Vec<Url>> = HashMap::new();

    let mut stream = watcher(services, wc).applied_objects().boxed();

    while let Some(result) = stream.next().await {
        match result {
            Ok(svc) => {
                if let Some((pool, url)) = service_to_origin(&svc) {
                    let svc_name = svc.metadata.name.as_deref().unwrap_or("unknown");
                    debug!("Discovered service {} -> pool {} at {}", svc_name, pool, url);

                    // Remove old entry for this service, then add new one
                    let entry = k8s_origins.entry(pool).or_default();
                    entry.clear();
                    entry.push(url);

                    rebuild_router(&state, &k8s_origins).await;
                }
            }
            Err(e) => {
                warn!("k8s watcher error: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }

    Ok(())
}
