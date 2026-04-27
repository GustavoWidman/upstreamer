use super::{LoadBalancer, OriginEndpoint, OriginState};
use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};

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
            if let Some(state) = origin_states.get(&origin.url_key)
                && state.healthy.load(Ordering::Relaxed)
            {
                return Some(origin.clone());
            }
        }

        None
    }
}
