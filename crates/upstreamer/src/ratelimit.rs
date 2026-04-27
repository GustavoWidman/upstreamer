use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Token bucket for rate limiting.
///
/// Each bucket tracks available tokens for a single client IP.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64,
    last_refill: Instant,
    last_used: Instant,
}

impl TokenBucket {
    /// Create a new token bucket, starting with a full bucket (tokens = burst).
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            tokens: burst as f64,
            max_tokens: burst as f64,
            refill_rate: rate as f64,
            last_refill: Instant::now(),
            last_used: Instant::now(),
        }
    }

    /// Try to consume one token.
    ///
    /// Returns true if a token was consumed (request allowed), false if rate limited.
    pub fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        // Refill tokens based on elapsed time
        let tokens_to_add = elapsed * self.refill_rate;
        self.tokens = (self.tokens + tokens_to_add).min(self.max_tokens);
        self.last_refill = now;
        self.last_used = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Check if this bucket has been idle longer than the given duration.
    pub fn is_stale(&self, max_idle: Duration) -> bool {
        self.last_used.elapsed() > max_idle
    }
}

/// Per-IP rate limiter using token buckets.
///
/// Each client IP gets its own token bucket, created on first request.
pub struct RateLimiter {
    buckets: DashMap<IpAddr, TokenBucket>,
    rate: u32,
    burst: u32,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// # Arguments
    /// * `rate` - Tokens to add per second (requests per second)
    /// * `burst` - Maximum bucket size (burst allowance)
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            buckets: DashMap::new(),
            rate,
            burst,
        }
    }

    /// Check if a request from the given IP should be allowed.
    ///
    /// Creates a new bucket for the IP on first request, then tries to consume a token.
    ///
    /// Returns true if the request is allowed, false if rate limited.
    pub fn check(&self, ip: IpAddr) -> bool {
        match self.buckets.entry(ip) {
            Entry::Occupied(mut e) => e.get_mut().try_consume(),
            Entry::Vacant(e) => {
                let mut bucket = TokenBucket::new(self.rate, self.burst);
                let allowed = bucket.try_consume();
                e.insert(bucket);
                allowed
            }
        }
    }

    /// Remove buckets that haven't been used recently.
    ///
    /// # Arguments
    /// * `max_idle` - Maximum idle duration before a bucket is considered stale
    pub fn cleanup_stale(&self, max_idle: Duration) {
        self.buckets.retain(|_, bucket| !bucket.is_stale(max_idle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_fresh_bucket_allows_requests() {
        let mut bucket = TokenBucket::new(10, 5);
        assert!(bucket.try_consume(), "Fresh bucket should allow request");
        assert_eq!(bucket.tokens, 4.0);
    }

    #[test]
    fn test_exceeding_burst_rate_limits() {
        let mut bucket = TokenBucket::new(10, 2);
        assert!(bucket.try_consume(), "First request should be allowed");
        assert!(bucket.try_consume(), "Second request should be allowed");
        assert!(!bucket.try_consume(), "Third request should be rate limited");
    }

    #[test]
    fn test_tokens_refill_over_time() {
        let mut bucket = TokenBucket::new(100, 5); // 100 tokens/sec

        // Exhaust bucket
        for _ in 0..5 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume(), "Should be rate limited after exhaustion");

        // Wait for at least one token to refill (100 tokens/sec = 10ms per token)
        thread::sleep(Duration::from_millis(20));

        assert!(bucket.try_consume(), "Should allow request after refill");
    }

    #[test]
    fn test_multiple_ips_independent_buckets() {
        let limiter = RateLimiter::new(10, 2);

        let ip1 = "127.0.0.1".parse().unwrap();
        let ip2 = "127.0.0.2".parse().unwrap();

        // Both IPs should be able to make burst requests
        assert!(limiter.check(ip1));
        assert!(limiter.check(ip1));
        assert!(!limiter.check(ip1));

        // IP2 should have its own bucket
        assert!(limiter.check(ip2));
        assert!(limiter.check(ip2));
        assert!(!limiter.check(ip2));
    }

    #[test]
    fn test_cleanup_stale_buckets() {
        let limiter = RateLimiter::new(10, 5);

        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "127.0.0.2".parse().unwrap();

        // Create buckets for both IPs
        limiter.check(ip1);
        limiter.check(ip2);

        assert_eq!(limiter.buckets.len(), 2);

        // Wait to make ip1's bucket stale (simulate by manipulating time indirectly)
        thread::sleep(Duration::from_millis(10));

        // Cleanup with very short max_idle - ip2 should be removed too since we just checked it
        // Actually, let's test with a longer sleep
        thread::sleep(Duration::from_millis(50));

        limiter.cleanup_stale(Duration::from_millis(20));

        // After cleanup, buckets older than 20ms should be gone
        // Since both were created >70ms ago, both should be cleaned
        assert_eq!(limiter.buckets.len(), 0);
    }

    #[test]
    fn test_is_stale() {
        let bucket = TokenBucket::new(10, 5);
        assert!(!bucket.is_stale(Duration::from_secs(1)));

        thread::sleep(Duration::from_millis(10));
        assert!(bucket.is_stale(Duration::from_millis(5)));
        assert!(!bucket.is_stale(Duration::from_millis(20)));
    }
}
