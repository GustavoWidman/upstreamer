use async_trait::async_trait;
use dashmap::DashMap;
use rand::Rng;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug)]
pub struct OriginEndpoint {
    pub url: Url,
    pub weight: Option<u32>,
    #[allow(dead_code)]
    pub health_check_path: Option<String>,
}

#[derive(Debug)]
pub struct OriginState {
    pub ewma_latency_ns: AtomicU64,
    pub consecutive_successes: AtomicU32,
    pub consecutive_failures: AtomicU32,
    pub total_requests: AtomicU64,
    pub total_failures: AtomicU64,
    pub healthy: AtomicBool,
}

impl OriginState {
    pub fn new() -> Self {
        Self {
            ewma_latency_ns: AtomicU64::new(0),
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
        }
    }

    pub fn record_latency(&self, latency: Duration) {
        const EWMA_ALPHA: f64 = 0.1;
        let sample_ns = latency.as_nanos() as u64;

        let mut old = self.ewma_latency_ns.load(Ordering::Relaxed);
        loop {
            let new = (EWMA_ALPHA * sample_ns as f64 + (1.0 - EWMA_ALPHA) * old as f64) as u64;
            match self.ewma_latency_ns.compare_exchange_weak(
                old,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual_old) => old = actual_old,
            }
        }
    }

    pub fn record_success(&self) {
        self.record_success_with_threshold(2);
    }

    pub fn record_failure(&self) {
        self.record_failure_with_threshold(5);
    }

    pub fn record_success_with_threshold(&self, threshold: u32) {
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;
        self.consecutive_failures.store(0, Ordering::Relaxed);
        if successes >= threshold {
            self.healthy.store(true, Ordering::Relaxed);
        }
    }

    pub fn record_failure_with_threshold(&self, threshold: u32) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        self.consecutive_successes.store(0, Ordering::Relaxed);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        if failures >= threshold {
            self.healthy.store(false, Ordering::Relaxed);
        }
    }

    pub fn increment_requests(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }
}

#[async_trait]
pub trait LoadBalancer: Send + Sync {
    async fn select_origin(
        &self,
        candidates: &[OriginEndpoint],
        origin_states: &DashMap<String, OriginState>,
    ) -> Option<OriginEndpoint>;
}

pub struct RoundRobinBalancer {
    counter: AtomicU64,
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for RoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LoadBalancer for RoundRobinBalancer {
    async fn select_origin(
        &self,
        candidates: &[OriginEndpoint],
        origin_states: &DashMap<String, OriginState>,
    ) -> Option<OriginEndpoint> {
        if candidates.is_empty() {
            return None;
        }

        let count = candidates.len();
        let start_idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % count;

        for i in 0..count {
            let idx = (start_idx + i) % count;
            let origin = &candidates[idx];
            if let Some(state) = origin_states.get(&origin.url.to_string())
                && state.healthy.load(Ordering::Relaxed)
            {
                return Some(origin.clone());
            }
        }

        None
    }
}

pub struct WeightedLatencyBalancer;

impl WeightedLatencyBalancer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WeightedLatencyBalancer {
    fn default() -> Self {
        Self::new()
    }
}

fn weighted_random_select(weights: &[f64]) -> usize {
    let total: f64 = weights.iter().sum();
    if total <= 0.0 {
        return rand::rng().random_range(0..weights.len());
    }

    let mut rng = rand::rng();
    let random = rng.random::<f64>() * total;

    let mut cumulative = 0.0;
    for (i, &w) in weights.iter().enumerate() {
        cumulative += w;
        if cumulative > random {
            return i;
        }
    }

    weights.len() - 1
}

#[async_trait]
impl LoadBalancer for WeightedLatencyBalancer {
    async fn select_origin(
        &self,
        candidates: &[OriginEndpoint],
        origin_states: &DashMap<String, OriginState>,
    ) -> Option<OriginEndpoint> {
        if candidates.is_empty() {
            return None;
        }

        let mut weights = Vec::with_capacity(candidates.len());
        for origin in candidates {
            let base_weight = if let Some(state) = origin_states.get(&origin.url.to_string()) {
                if !state.healthy.load(Ordering::Relaxed) {
                    weights.push(0.0);
                    continue;
                }

                let latency_ns = state.ewma_latency_ns.load(Ordering::Relaxed);
                if latency_ns == 0 {
                    1.0
                } else {
                    1.0 / (latency_ns as f64 + 1.0)
                }
            } else {
                1.0
            };

            let weight = if let Some(user_weight) = origin.weight {
                base_weight * user_weight as f64
            } else {
                base_weight
            };

            weights.push(weight);
        }

        let idx = weighted_random_select(&weights);
        if weights[idx] > 0.0 {
            Some(candidates[idx].clone())
        } else {
            None
        }
    }
}

pub struct WeightedMetricsBalancer;

impl WeightedMetricsBalancer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WeightedMetricsBalancer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LoadBalancer for WeightedMetricsBalancer {
    async fn select_origin(
        &self,
        candidates: &[OriginEndpoint],
        origin_states: &DashMap<String, OriginState>,
    ) -> Option<OriginEndpoint> {
        if candidates.is_empty() {
            return None;
        }

        let mut weights = Vec::with_capacity(candidates.len());
        for origin in candidates {
            let base_weight = if let Some(state) = origin_states.get(&origin.url.to_string()) {
                if !state.healthy.load(Ordering::Relaxed) {
                    weights.push(0.0);
                    continue;
                }

                const DEFAULT_PRESSURE: f64 = 0.0;
                let pressure = DEFAULT_PRESSURE;
                let metrics_weight = (1000.0 - pressure).max(0.0);

                if metrics_weight < 100.0 {
                    let latency_ns = state.ewma_latency_ns.load(Ordering::Relaxed);
                    if latency_ns > 0 {
                        metrics_weight * (1.0 / (latency_ns as f64 + 1.0))
                    } else {
                        metrics_weight
                    }
                } else {
                    metrics_weight
                }
            } else {
                1000.0
            };

            let weight = if let Some(user_weight) = origin.weight {
                base_weight * user_weight as f64
            } else {
                base_weight
            };

            weights.push(weight);
        }

        let idx = weighted_random_select(&weights);
        if weights[idx] > 0.0 {
            Some(candidates[idx].clone())
        } else {
            None
        }
    }
}
