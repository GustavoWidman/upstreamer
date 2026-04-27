use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("route '{route}' has no pools configured")]
    RouteHasNoPools { route: String },

    #[error("route '{route}' pool '{pool}' has no origins")]
    PoolHasNoOrigins { route: String, pool: String },

    #[error("route '{route}' pool '{pool}' origin '{origin}' has invalid URL: {reason}")]
    InvalidOriginUrl {
        route: String,
        pool: String,
        origin: String,
        reason: String,
    },

    #[error(
        "route '{route}' pool '{pool}' origin '{origin}' uses HTTPS scheme (not supported in v1)"
    )]
    HttpsNotSupported {
        route: String,
        pool: String,
        origin: String,
    },

    #[error("rate limit must have rate > 0 and burst > 0")]
    InvalidRateLimit,

    #[error("duplicate route match: host '{}' path '{}'", host.as_deref().unwrap_or("*"), path.as_deref().unwrap_or("*"))]
    DuplicateRouteMatch {
        host: Option<String>,
        path: Option<String>,
    },

    #[error("invalid socket address '{addr}': {reason}")]
    #[allow(dead_code)]
    InvalidSocketAddr { addr: String, reason: String },

    #[error("error pages directory '{path}' does not exist")]
    ErrorPagesDirectoryNotFound { path: PathBuf },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_metrics_addr")]
    pub metrics_addr: SocketAddr,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub ratelimit: Option<RateLimitConfig>,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub kubernetes: Option<KubernetesConfig>,
    #[serde(default)]
    pub error_pages: Option<ErrorPagesConfig>,
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:8080".parse().unwrap()
}

fn default_metrics_addr() -> SocketAddr {
    "0.0.0.0:9090".parse().unwrap()
}

impl ProxyConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config from '{}'", path.display()))?;

        let config: ProxyConfig = toml::from_str(&contents)
            .with_context(|| format!("failed to parse TOML from '{}'", path.display()))?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Track route matches to detect duplicates
        let mut seen_matches: Vec<(Option<String>, Option<String>)> = Vec::new();

        for (route_idx, route) in self.routes.iter().enumerate() {
            let route_name = route
                .match_host
                .clone()
                .or_else(|| route.match_path.clone())
                .unwrap_or_else(|| format!("index-{}", route_idx));

            // Check for duplicate matches
            let match_key = (route.match_host.clone(), route.match_path.clone());
            if seen_matches.contains(&match_key) {
                return Err(ConfigError::DuplicateRouteMatch {
                    host: route.match_host.clone(),
                    path: route.match_path.clone(),
                }
                .into());
            }
            seen_matches.push(match_key);

            // Validate pools
            if route.pools.is_empty() {
                return Err(ConfigError::RouteHasNoPools { route: route_name }.into());
            }

            for pool in &route.pools {
                if pool.origins.is_empty() {
                    return Err(ConfigError::PoolHasNoOrigins {
                        route: route_name.clone(),
                        pool: pool.name.clone(),
                    }
                    .into());
                }

                for origin in &pool.origins {
                    let origin_str = origin.url.to_string();

                    // Validate URL scheme
                    if origin.url.scheme() != "http" {
                        if origin.url.scheme() == "https" {
                            return Err(ConfigError::HttpsNotSupported {
                                route: route_name.clone(),
                                pool: pool.name.clone(),
                                origin: origin_str,
                            }
                            .into());
                        } else {
                            return Err(ConfigError::InvalidOriginUrl {
                                route: route_name.clone(),
                                pool: pool.name.clone(),
                                origin: origin_str,
                                reason: format!("invalid scheme '{}'", origin.url.scheme()),
                            }
                            .into());
                        }
                    }
                }
            }

            // Validate per-route rate limit
            if let Some(ref rl) = route.ratelimit
                && (rl.rate == 0 || rl.burst == 0)
            {
                return Err(ConfigError::InvalidRateLimit.into());
            }
        }

        // Validate global rate limit
        if let Some(ref rl) = self.ratelimit
            && (rl.rate == 0 || rl.burst == 0)
        {
            return Err(ConfigError::InvalidRateLimit.into());
        }

        // Validate error pages directory
        if let Some(ref pages) = self.error_pages
            && !pages.directory.exists()
        {
            return Err(ConfigError::ErrorPagesDirectoryNotFound {
                path: pages.directory.clone(),
            }
            .into());
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteConfig {
    #[serde(default)]
    pub match_host: Option<String>,
    #[serde(default)]
    pub match_path: Option<String>,
    pub pools: Vec<PoolRef>,
    #[serde(default = "default_lb_algorithm")]
    pub lb_algorithm: LbAlgorithm,
    #[serde(default)]
    pub ratelimit: Option<RateLimitConfig>,
}

fn default_lb_algorithm() -> LbAlgorithm {
    LbAlgorithm::RoundRobin
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbAlgorithm {
    RoundRobin,
    WeightedLatency,
    WeightedMetrics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolRef {
    pub name: String,
    pub origins: Vec<OriginConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OriginConfig {
    pub url: Url,
    #[serde(default)]
    pub weight: Option<u32>,
    #[serde(default)]
    pub health_check_path: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub rate: u32,
    pub burst: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HealthConfig {
    #[serde(default)]
    pub active: ActiveHealthConfig,
    #[serde(default)]
    pub passive: PassiveHealthConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveHealthConfig {
    #[serde(default = "default_active_enabled")]
    pub enabled: bool,
    #[serde(default = "default_active_interval")]
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    #[serde(default = "default_active_timeout")]
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_active_enabled() -> bool {
    true
}

fn default_active_interval() -> Duration {
    Duration::from_secs(10)
}

fn default_active_timeout() -> Duration {
    Duration::from_secs(5)
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_unhealthy_threshold() -> u32 {
    3
}

impl Default for ActiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: default_active_enabled(),
            interval: default_active_interval(),
            timeout: default_active_timeout(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PassiveHealthConfig {
    #[serde(default = "default_passive_enabled")]
    pub enabled: bool,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    #[serde(default = "default_observation_window")]
    #[serde(with = "humantime_serde")]
    pub observation_window: Duration,
}

fn default_passive_enabled() -> bool {
    true
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_success_threshold() -> u32 {
    2
}

fn default_observation_window() -> Duration {
    Duration::from_secs(60)
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: default_passive_enabled(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            observation_window: default_observation_window(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub label_selector: Option<String>,
    #[serde(default = "default_poll_interval")]
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
}

fn default_poll_interval() -> Duration {
    Duration::from_secs(30)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorPage {
    pub code: u16,
    pub file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorPagesConfig {
    pub directory: PathBuf,
    pub pages: Vec<ErrorPage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_listen() {
        let addr = default_listen();
        assert_eq!(addr.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn test_default_lb_algorithm() {
        let algo = default_lb_algorithm();
        assert!(matches!(algo, LbAlgorithm::RoundRobin));
    }

    #[test]
    fn test_validate_empty_route() {
        let config = ProxyConfig {
            listen: default_listen(),
            metrics_addr: default_metrics_addr(),
            routes: vec![RouteConfig {
                match_host: None,
                match_path: Some("/".to_string()),
                pools: vec![],
                lb_algorithm: LbAlgorithm::RoundRobin,
                ratelimit: None,
            }],
            ratelimit: None,
            health: HealthConfig::default(),
            kubernetes: None,
            error_pages: None,
        };

        let result = config.validate();
        assert!(result.is_err());
    }
}
