use crate::balance::OriginEndpoint;
use crate::config::parser::{LbAlgorithm, ProxyConfig, RouteConfig};
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;

pub struct Router {
    routes: Vec<RouteEntry>,
}

pub struct RouteEntry {
    match_host: Option<String>,
    match_path: Option<String>,
    key: String,
    #[allow(dead_code)]
    config: RouteConfig,
    load_balancer: Arc<dyn crate::balance::LoadBalancer>,
    candidates: Vec<OriginEndpoint>,
}

impl RouteEntry {
    pub fn load_balancer(&self) -> &Arc<dyn crate::balance::LoadBalancer> {
        &self.load_balancer
    }

    pub fn candidates(&self) -> &[OriginEndpoint] {
        &self.candidates
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Router {
    pub fn from_config(config: &ProxyConfig) -> Self {
        let routes = config
            .routes
            .iter()
            .map(|route| {
                let load_balancer: Arc<dyn crate::balance::LoadBalancer> = match route.lb_algorithm
                {
                    LbAlgorithm::RoundRobin => Arc::new(crate::balance::RoundRobinBalancer::new()),
                    LbAlgorithm::WeightedLatency => {
                        Arc::new(crate::balance::WeightedLatencyBalancer::new())
                    }
                    LbAlgorithm::WeightedMetrics => {
                        Arc::new(crate::balance::WeightedMetricsBalancer::new())
                    }
                };

                let mut candidates = Vec::new();
                for pool in &route.pools {
                    for origin in &pool.origins {
                        let url = &origin.url;
                        candidates.push(OriginEndpoint {
                            url: url.clone(),
                            url_key: url.to_string(),
                            url_base: url.as_str().trim_end_matches('/').to_string(),
                            weight: origin.weight,
                            health_check_path: origin.health_check_path.clone(),
                        });
                    }
                }

                let key = format!(
                    "{}:{}",
                    route.match_host.as_deref().unwrap_or("*"),
                    route.match_path.as_deref().unwrap_or("*")
                );

                RouteEntry {
                    match_host: route.match_host.clone(),
                    match_path: route.match_path.clone(),
                    key,
                    config: route.clone(),
                    load_balancer,
                    candidates,
                }
            })
            .collect();

        Self { routes }
    }

    pub fn from_config_with_k8s(
        config: &ProxyConfig,
        k8s_origins: &HashMap<String, Vec<Url>>,
    ) -> Self {
        let routes = config
            .routes
            .iter()
            .map(|route| {
                let load_balancer: Arc<dyn crate::balance::LoadBalancer> = match route.lb_algorithm
                {
                    LbAlgorithm::RoundRobin => Arc::new(crate::balance::RoundRobinBalancer::new()),
                    LbAlgorithm::WeightedLatency => {
                        Arc::new(crate::balance::WeightedLatencyBalancer::new())
                    }
                    LbAlgorithm::WeightedMetrics => {
                        Arc::new(crate::balance::WeightedMetricsBalancer::new())
                    }
                };

                let mut candidates = Vec::new();
                for pool in &route.pools {
                    // Static origins from config
                    for origin in &pool.origins {
                        let url = &origin.url;
                        candidates.push(OriginEndpoint {
                            url: url.clone(),
                            url_key: url.to_string(),
                            url_base: url.as_str().trim_end_matches('/').to_string(),
                            weight: origin.weight,
                            health_check_path: origin.health_check_path.clone(),
                        });
                    }
                    // k8s-discovered origins matching this pool name
                    if let Some(k8s_urls) = k8s_origins.get(&pool.name) {
                        for url in k8s_urls {
                            candidates.push(OriginEndpoint {
                                url: url.clone(),
                                url_key: url.to_string(),
                                url_base: url.as_str().trim_end_matches('/').to_string(),
                                weight: None,
                                health_check_path: None,
                            });
                        }
                    }
                }

                let key = format!(
                    "{}:{}",
                    route.match_host.as_deref().unwrap_or("*"),
                    route.match_path.as_deref().unwrap_or("*")
                );

                RouteEntry {
                    match_host: route.match_host.clone(),
                    match_path: route.match_path.clone(),
                    key,
                    config: route.clone(),
                    load_balancer,
                    candidates,
                }
            })
            .collect();

        Self { routes }
    }

    pub fn match_route(&self, host: &str, path: &str) -> Option<&RouteEntry> {
        for route in &self.routes {
            let host_match = match &route.match_host {
                Some(pattern) => self.match_glob(host, pattern),
                None => true,
            };

            if !host_match {
                continue;
            }

            let path_match = match &route.match_path {
                Some(prefix) => path.starts_with(prefix),
                None => true,
            };

            if path_match {
                return Some(route);
            }
        }

        None
    }

    fn match_glob(&self, value: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if pattern.contains('*') {
            let parts: Vec<&str> = pattern.split('*').collect();
            if parts.len() == 2 {
                let (prefix, suffix) = (parts[0], parts[1]);
                return value.starts_with(prefix) && value.ends_with(suffix);
            }
        }

        value == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::PoolRef;

    #[test]
    fn test_match_glob_exact() {
        let router = Router { routes: vec![] };
        assert!(router.match_glob("example.com", "example.com"));
        assert!(!router.match_glob("example.com", "other.com"));
    }

    #[test]
    fn test_match_glob_wildcard() {
        let router = Router { routes: vec![] };
        assert!(router.match_glob("example.com", "*"));
        assert!(router.match_glob("anything", "*"));
    }

    #[test]
    fn test_match_glob_pattern() {
        let router = Router { routes: vec![] };
        assert!(router.match_glob("foo.example.com", "*.example.com"));
        assert!(router.match_glob("bar.example.com", "*.example.com"));
        assert!(!router.match_glob("example.com", "*.example.com"));
        assert!(!router.match_glob("foo.other.com", "*.example.com"));
    }

    #[test]
    fn test_match_route() {
        let config = ProxyConfig {
            listen: "0.0.0.0:8080".parse().unwrap(),
            metrics_addr: "0.0.0.0:9090".parse().unwrap(),
            routes: vec![
                RouteConfig {
                    match_host: Some("example.com".to_string()),
                    match_path: Some("/api".to_string()),
                    pools: vec![PoolRef {
                        name: "pool1".to_string(),
                        origins: vec![],
                    }],
                    lb_algorithm: LbAlgorithm::RoundRobin,
                    ratelimit: None,
                },
                RouteConfig {
                    match_host: Some("*.test.com".to_string()),
                    match_path: None,
                    pools: vec![PoolRef {
                        name: "pool2".to_string(),
                        origins: vec![],
                    }],
                    lb_algorithm: LbAlgorithm::RoundRobin,
                    ratelimit: None,
                },
            ],
            ratelimit: None,
            health: Default::default(),
            kubernetes: None,
            error_pages: None,
        };

        let router = Router::from_config(&config);

        assert!(router.match_route("example.com", "/api/test").is_some());
        assert!(router.match_route("example.com", "/api").is_some());
        assert!(router.match_route("example.com", "/other").is_none());
        assert!(router.match_route("foo.test.com", "/anything").is_some());
        assert!(router.match_route("other.com", "/api").is_none());
    }
}
