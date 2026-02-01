//! Per-tenant rate limiting using a token bucket algorithm.
//!
//! Each tenant has an isolated rate limit state backed by [`CacheLayer`].
//! In production this means Redis-backed state shared across proxy
//! instances; in development the in-memory cache provides single-instance
//! rate limiting.
//!
//! Cache key format: `ratelimit:{tenant_id}:{window_key}`

use chrono::Utc;
use llmtrace_core::{CacheLayer, RateLimitConfig, TenantId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

/// State for a single token bucket stored in the cache layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenBucketState {
    /// Current number of available tokens.
    tokens: f64,
    /// Timestamp (seconds since epoch) of the last token refill.
    last_refill_epoch: f64,
}

/// Per-tenant rate limiter backed by [`CacheLayer`].
pub struct RateLimiter {
    config: RateLimitConfig,
    cache: Arc<dyn CacheLayer>,
}

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed,
    /// Request is rejected — rate limit exceeded.
    Exceeded {
        /// Seconds until the next token becomes available.
        retry_after_secs: u64,
        /// Configured requests per second for this tenant.
        limit: u32,
        /// Tenant whose limit was exceeded.
        tenant_id: TenantId,
    },
}

impl RateLimiter {
    /// Create a new rate limiter with the given config and cache backend.
    pub fn new(config: &RateLimitConfig, cache: Arc<dyn CacheLayer>) -> Self {
        Self {
            config: config.clone(),
            cache,
        }
    }

    /// Resolve the effective rate limit parameters for a tenant.
    fn resolve_limits(&self, tenant_id: TenantId) -> (u32, u32) {
        let tenant_key = tenant_id.0.to_string();
        if let Some(overrides) = self.config.tenant_overrides.get(&tenant_key) {
            (overrides.requests_per_second, overrides.burst_size)
        } else {
            (self.config.requests_per_second, self.config.burst_size)
        }
    }

    /// Cache key for a tenant's token bucket.
    fn cache_key(tenant_id: TenantId) -> String {
        let now = Utc::now();
        // Use a window key based on the current minute to naturally expire
        // stale buckets. The TTL on the cache entry ensures cleanup.
        let window = now.format("%Y%m%d%H%M").to_string();
        format!("ratelimit:{}:{}", tenant_id.0, window)
    }

    /// Check (and consume one token from) the rate limit for a tenant.
    ///
    /// Returns [`RateLimitResult::Allowed`] if the request may proceed, or
    /// [`RateLimitResult::Exceeded`] with a retry-after hint if the tenant
    /// has exhausted their budget.
    pub async fn check(&self, tenant_id: TenantId) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        let (rps, burst) = self.resolve_limits(tenant_id);
        if rps == 0 {
            return RateLimitResult::Allowed;
        }

        let key = Self::cache_key(tenant_id);
        let now_epoch = Utc::now().timestamp_millis() as f64 / 1000.0;

        // Load existing state from cache
        let mut bucket = match self.cache.get(&key).await {
            Ok(Some(bytes)) => {
                serde_json::from_slice::<TokenBucketState>(&bytes).unwrap_or(TokenBucketState {
                    tokens: burst as f64,
                    last_refill_epoch: now_epoch,
                })
            }
            _ => TokenBucketState {
                tokens: burst as f64,
                last_refill_epoch: now_epoch,
            },
        };

        // Refill tokens based on elapsed time
        let elapsed = (now_epoch - bucket.last_refill_epoch).max(0.0);
        let refill = elapsed * rps as f64;
        bucket.tokens = (bucket.tokens + refill).min(burst as f64);
        bucket.last_refill_epoch = now_epoch;

        // Try to consume one token
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            // Persist updated state
            if let Ok(bytes) = serde_json::to_vec(&bucket) {
                let _ = self.cache.set(&key, &bytes, Duration::from_secs(120)).await;
            }
            debug!(
                tenant_id = %tenant_id,
                tokens_remaining = bucket.tokens,
                "Rate limit check: allowed"
            );
            RateLimitResult::Allowed
        } else {
            // Persist state so the refill timestamp stays accurate
            if let Ok(bytes) = serde_json::to_vec(&bucket) {
                let _ = self.cache.set(&key, &bytes, Duration::from_secs(120)).await;
            }
            // Calculate retry-after: time until at least one token is available
            let deficit = 1.0 - bucket.tokens;
            let wait_secs = (deficit / rps as f64).ceil() as u64;
            let retry_after = wait_secs.max(1);
            debug!(
                tenant_id = %tenant_id,
                retry_after_secs = retry_after,
                "Rate limit check: exceeded"
            );
            RateLimitResult::Exceeded {
                retry_after_secs: retry_after,
                limit: rps,
                tenant_id,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::TenantRateLimitOverride;
    use llmtrace_storage::InMemoryCacheLayer;
    use std::collections::HashMap;

    fn make_config(rps: u32, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            enabled: true,
            requests_per_second: rps,
            burst_size: burst,
            window_seconds: 60,
            tenant_overrides: HashMap::new(),
        }
    }

    fn make_limiter(config: &RateLimitConfig) -> RateLimiter {
        let cache = Arc::new(InMemoryCacheLayer::new());
        RateLimiter::new(config, cache)
    }

    #[tokio::test]
    async fn test_allowed_under_limit() {
        let config = make_config(100, 200);
        let limiter = make_limiter(&config);
        let tenant = TenantId::new();

        let result = limiter.check(tenant).await;
        assert!(matches!(result, RateLimitResult::Allowed));
    }

    #[tokio::test]
    async fn test_burst_handling() {
        // Very low burst: 3 tokens, 1 rps
        let config = make_config(1, 3);
        let limiter = make_limiter(&config);
        let tenant = TenantId::new();

        // Should allow 3 requests (burst)
        for _ in 0..3 {
            let result = limiter.check(tenant).await;
            assert!(matches!(result, RateLimitResult::Allowed));
        }

        // 4th request should be rejected
        let result = limiter.check(tenant).await;
        assert!(matches!(result, RateLimitResult::Exceeded { .. }));
    }

    #[tokio::test]
    async fn test_per_tenant_isolation() {
        let config = make_config(1, 2);
        let cache = Arc::new(InMemoryCacheLayer::new());
        let limiter = RateLimiter::new(&config, cache);

        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();

        // Exhaust tenant A's budget
        let _ = limiter.check(tenant_a).await;
        let _ = limiter.check(tenant_a).await;
        let result_a = limiter.check(tenant_a).await;
        assert!(matches!(result_a, RateLimitResult::Exceeded { .. }));

        // Tenant B should still have budget
        let result_b = limiter.check(tenant_b).await;
        assert!(matches!(result_b, RateLimitResult::Allowed));
    }

    #[tokio::test]
    async fn test_tenant_overrides() {
        let mut overrides = HashMap::new();
        let special_tenant = TenantId::new();
        overrides.insert(
            special_tenant.0.to_string(),
            TenantRateLimitOverride {
                requests_per_second: 500,
                burst_size: 1000,
            },
        );

        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 2,
            window_seconds: 60,
            tenant_overrides: overrides,
        };

        let cache = Arc::new(InMemoryCacheLayer::new());
        let limiter = RateLimiter::new(&config, cache);

        let default_tenant = TenantId::new();

        // Default tenant has burst=2, so 3rd request fails
        let _ = limiter.check(default_tenant).await;
        let _ = limiter.check(default_tenant).await;
        let result = limiter.check(default_tenant).await;
        assert!(matches!(result, RateLimitResult::Exceeded { .. }));

        // Special tenant has burst=1000, so many requests succeed
        for _ in 0..100 {
            let result = limiter.check(special_tenant).await;
            assert!(matches!(result, RateLimitResult::Allowed));
        }
    }

    #[tokio::test]
    async fn test_disabled_rate_limiting() {
        let config = RateLimitConfig {
            enabled: false,
            requests_per_second: 1,
            burst_size: 1,
            window_seconds: 60,
            tenant_overrides: HashMap::new(),
        };
        let limiter = make_limiter(&config);
        let tenant = TenantId::new();

        // Even with burst=1, disabled means always allowed
        for _ in 0..100 {
            let result = limiter.check(tenant).await;
            assert!(matches!(result, RateLimitResult::Allowed));
        }
    }

    #[tokio::test]
    async fn test_exceeded_includes_retry_after() {
        let config = make_config(1, 1);
        let limiter = make_limiter(&config);
        let tenant = TenantId::new();

        // First request succeeds
        let _ = limiter.check(tenant).await;

        // Second request is rejected with retry info
        let result = limiter.check(tenant).await;
        match result {
            RateLimitResult::Exceeded {
                retry_after_secs,
                limit,
                tenant_id,
            } => {
                assert!(retry_after_secs >= 1);
                assert_eq!(limit, 1);
                assert_eq!(tenant_id, tenant);
            }
            _ => panic!("Expected Exceeded result"),
        }
    }
}
