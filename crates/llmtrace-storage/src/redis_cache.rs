//! Redis-backed cache layer implementation.
//!
//! Uses [`redis::aio::ConnectionManager`] for automatic reconnection and
//! pipelining. Intended for production deployments; see [`InMemoryCacheLayer`]
//! for a zero-infrastructure alternative.
//!
//! Gated behind the `redis_backend` Cargo feature.

use async_trait::async_trait;
use llmtrace_core::{CacheLayer, LLMTraceError, Result};
use redis::AsyncCommands;
use std::time::Duration;

/// Redis-backed cache layer with automatic reconnection.
///
/// Uses `SET EX` for writes (with TTL), `GET` for reads, `DEL` for
/// invalidation, and `PING` for health checks.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> llmtrace_core::Result<()> {
/// use llmtrace_core::CacheLayer;
/// let cache = llmtrace_storage::RedisCacheLayer::new("redis://127.0.0.1:6379").await?;
/// cache.health_check().await?;
/// # Ok(())
/// # }
/// ```
pub struct RedisCacheLayer {
    conn: redis::aio::ConnectionManager,
}

impl RedisCacheLayer {
    /// Connect to a Redis instance.
    ///
    /// The `url` should be a valid Redis connection string,
    /// e.g. `redis://127.0.0.1:6379` or `redis://:password@host:port/db`.
    pub async fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid Redis URL: {e}")))?;
        let conn = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to connect to Redis: {e}")))?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl CacheLayer for RedisCacheLayer {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn.clone();
        let result: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Redis GET failed: {e}")))?;
        Ok(result)
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        let mut conn = self.conn.clone();
        let seconds = ttl.as_secs().max(1);
        conn.set_ex::<_, _, ()>(key, value, seconds)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Redis SET EX failed: {e}")))?;
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(key)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Redis DEL failed: {e}")))?;
        Ok(())
    }

    async fn health_check(&self) -> Result<()> {
        let mut conn = self.conn.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Redis PING failed: {e}")))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Return a [`RedisCacheLayer`] connected to the test instance,
    /// or panic if `LLMTRACE_REDIS_URL` is not set.
    async fn test_cache() -> RedisCacheLayer {
        let url =
            env::var("LLMTRACE_REDIS_URL").expect("LLMTRACE_REDIS_URL must be set for Redis tests");
        RedisCacheLayer::new(&url).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_set_and_get() {
        let cache = test_cache().await;
        cache
            .set("test:key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("test:key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_get_missing_key() {
        let cache = test_cache().await;
        let result = cache.get("test:nonexistent_key_abc123").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_ttl_expiry() {
        let cache = test_cache().await;
        cache
            .set("test:ephemeral", b"data", Duration::from_secs(1))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.get("test:ephemeral").await.unwrap().is_some());

        // Wait for expiry
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be gone
        assert!(cache.get("test:ephemeral").await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_invalidate() {
        let cache = test_cache().await;
        cache
            .set("test:inv_key", b"val", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(cache.get("test:inv_key").await.unwrap().is_some());

        cache.invalidate("test:inv_key").await.unwrap();
        assert!(cache.get("test:inv_key").await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_invalidate_missing_key_is_noop() {
        let cache = test_cache().await;
        // Should not error
        cache.invalidate("test:missing_inv_key_xyz").await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_overwrite_existing_key() {
        let cache = test_cache().await;
        cache
            .set("test:ow_key", b"v1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("test:ow_key", b"v2", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("test:ow_key").await.unwrap();
        assert_eq!(result, Some(b"v2".to_vec()));
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_health_check() {
        let cache = test_cache().await;
        assert!(cache.health_check().await.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires a running Redis instance"]
    async fn test_binary_data_roundtrip() {
        let cache = test_cache().await;
        let data: Vec<u8> = (0u8..=255).collect();
        cache
            .set("test:binary", &data, Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("test:binary").await.unwrap().unwrap();
        assert_eq!(result, data);
    }
}
