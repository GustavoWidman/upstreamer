mod round_robin;
mod weighted;

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug)]
pub struct OriginEndpoint {
    pub url: Url,
    pub url_key: String,
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

impl Default for OriginState {
    fn default() -> Self {
        Self::new()
    }
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
        let sample_ns = latency.as_nanos() as u64;
        let mut old = self.ewma_latency_ns.load(Ordering::Relaxed);
        loop {
            // α=0.1 EWMA as integer math: new = (sample + 9*old) / 10
            let new = (sample_ns + 9 * old) / 10;
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

pub use round_robin::RoundRobinBalancer;
pub use weighted::{WeightedLatencyBalancer, WeightedMetricsBalancer};
