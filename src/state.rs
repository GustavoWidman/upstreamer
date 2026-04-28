use crate::balance::OriginState;
use crate::config::parser::ProxyConfig;
use crate::middleware::errors::ErrorPageStore;
use crate::middleware::ratelimit::RateLimiter;
use crate::route::Router;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::Full;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use metrics_exporter_prometheus::PrometheusHandle;
use std::sync::atomic::{AtomicBool, AtomicU32};

pub struct AppState {
    pub config: ArcSwap<ProxyConfig>,
    pub router: ArcSwap<Router>,
    pub client: Client<HttpConnector, Full<Bytes>>,
    pub origin_states: DashMap<String, OriginState>,
    pub ratelimiter: Option<RateLimiter>,
    pub route_ratelimiters: DashMap<String, RateLimiter>,
    pub metrics_handle: PrometheusHandle,
    pub error_pages: Option<ErrorPageStore>,
    pub passive_enabled: AtomicBool,
    pub passive_failure_threshold: AtomicU32,
    pub passive_success_threshold: AtomicU32,
}

impl AppState {
    pub fn new(config: ProxyConfig, metrics_handle: PrometheusHandle) -> Self {
        let router = Router::from_config(&config);
        let states = DashMap::new();
        for route in &config.routes {
            for pool in &route.pools {
                for origin in &pool.origins {
                    states.entry(origin.url.to_string()).or_default();
                }
            }
        }
        let client = Client::builder(TokioExecutor::new()).build(HttpConnector::new());

        let error_pages = config.error_pages.as_ref().map(ErrorPageStore::from_config);

        // Initialize global rate limiter if configured
        let ratelimiter = config
            .ratelimit
            .as_ref()
            .map(|rl| RateLimiter::new(rl.rate, rl.burst));

        // Initialize per-route rate limiters
        let route_ratelimiters = DashMap::new();
        for route in &config.routes {
            if let Some(ref rl) = route.ratelimit {
                let key = Self::route_key(&route.match_host, &route.match_path);
                route_ratelimiters.insert(key, RateLimiter::new(rl.rate, rl.burst));
            }
        }

        let passive_enabled = AtomicBool::new(config.health.passive.enabled);
        let passive_failure_threshold = AtomicU32::new(config.health.passive.failure_threshold);
        let passive_success_threshold = AtomicU32::new(config.health.passive.success_threshold);

        Self {
            config: ArcSwap::from_pointee(config),
            router: ArcSwap::from_pointee(router),
            client,
            origin_states: states,
            ratelimiter,
            route_ratelimiters,
            metrics_handle,
            error_pages,
            passive_enabled,
            passive_failure_threshold,
            passive_success_threshold,
        }
    }

    fn route_key(match_host: &Option<String>, match_path: &Option<String>) -> String {
        format!(
            "{}:{}",
            match_host.as_deref().unwrap_or("*"),
            match_path.as_deref().unwrap_or("*")
        )
    }
}
