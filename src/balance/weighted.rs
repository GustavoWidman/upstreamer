use super::{LoadBalancer, OriginEndpoint, OriginState};
use dashmap::DashMap;
use rand::Rng;
use std::sync::atomic::Ordering;

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

impl LoadBalancer for WeightedLatencyBalancer {
    fn select_origin<'a>(
        &self,
        candidates: &'a [OriginEndpoint],
        origin_states: &DashMap<String, OriginState>,
    ) -> Option<&'a OriginEndpoint> {
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
            Some(&candidates[idx])
        } else {
            None
        }
    }
}

impl LoadBalancer for WeightedMetricsBalancer {
    fn select_origin<'a>(
        &self,
        candidates: &'a [OriginEndpoint],
        origin_states: &DashMap<String, OriginState>,
    ) -> Option<&'a OriginEndpoint> {
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
            Some(&candidates[idx])
        } else {
            None
        }
    }
}
