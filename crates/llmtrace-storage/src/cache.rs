//! In-memory cache layer implementation.
//!
//! Uses [`DashMap`] with per-entry TTL expiry. Intended for dev/test use;
//! production deployments would use a Redis-backed implementation.

use async_trait::async_trait;
use dashmap::DashMap;
use llmtrace_core::{CacheLayer, Result};
use std::time::{Duration, Instant};

/// A cached value with its expiry instant.
struct CacheEntry {
    data: Vec<u8>,
    expires_at: Instant,
}

/// In-memory cache backed by [`DashMap`] with TTL expiry.
///
/// Expired entries are lazily evicted on access. This is suitable for
/// development and testing; production should use a Redis-backed cache.
pub struct InMemoryCacheLayer {
    map: DashMap<String, CacheEntry>,
}

impl InMemoryCacheLayer {
    /// Create a new, empty in-memory cache.
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }
}

impl Default for InMemoryCacheLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheLayer for InMemoryCacheLayer {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if let Some(entry) = self.map.get(key) {
            if Instant::now() < entry.expires_at {
                return Ok(Some(entry.data.clone()));
            }
            // Entry expired — drop the ref before removing
            drop(entry);
            self.map.remove(key);
        }
        Ok(None)
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> Result<()> {
        self.map.insert(
            key.to_string(),
            CacheEntry {
                data: value.to_vec(),
                expires_at: Instant::now() + ttl,
            },
        );
        Ok(())
    }

    async fn invalidate(&self, key: &str) -> Result<()> {
        self.map.remove(key);
        Ok(())
    }

    async fn health_check(&self) -> Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get() {
        let cache = InMemoryCacheLayer::new();
        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_get_missing_key() {
        let cache = InMemoryCacheLayer::new();
        let result = cache.get("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let cache = InMemoryCacheLayer::new();
        cache
            .set("ephemeral", b"data", Duration::from_millis(10))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.get("ephemeral").await.unwrap().is_some());

        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should be gone
        assert!(cache.get("ephemeral").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = InMemoryCacheLayer::new();
        cache
            .set("key", b"val", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(cache.get("key").await.unwrap().is_some());

        cache.invalidate("key").await.unwrap();
        assert!(cache.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_invalidate_missing_key_is_noop() {
        let cache = InMemoryCacheLayer::new();
        // Should not error
        cache.invalidate("missing").await.unwrap();
    }

    #[tokio::test]
    async fn test_overwrite_existing_key() {
        let cache = InMemoryCacheLayer::new();
        cache
            .set("key", b"v1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("key", b"v2", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("key").await.unwrap();
        assert_eq!(result, Some(b"v2".to_vec()));
    }

    #[tokio::test]
    async fn test_health_check() {
        let cache = InMemoryCacheLayer::new();
        assert!(cache.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_default() {
        let cache = InMemoryCacheLayer::default();
        assert!(cache.get("anything").await.unwrap().is_none());
    }
}
