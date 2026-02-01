//! Storage abstraction layer for LLMTrace
//!
//! Provides storage backends for persisting traces, metadata, and cache.
//! The primary backend is SQLite (via `sqlx`), with in-memory backends for testing.
//!
//! Use [`StorageProfile`] to build a complete [`Storage`] composite from a
//! configuration profile.

mod cache;
mod memory;
mod sqlite;

#[cfg(feature = "clickhouse")]
mod clickhouse;

pub use cache::InMemoryCacheLayer;
pub use memory::{InMemoryMetadataRepository, InMemoryTraceRepository};
pub use sqlite::{SqliteMetadataRepository, SqliteTraceRepository};

#[cfg(feature = "clickhouse")]
pub use self::clickhouse::ClickHouseTraceRepository;

use llmtrace_core::{Result, Storage};
use std::sync::Arc;

/// Storage configuration profile.
///
/// Determines which backend implementations are wired together when
/// building a [`Storage`] composite via [`StorageProfile::build`].
pub enum StorageProfile {
    /// SQLite for everything — zero infrastructure.
    Lite {
        /// Path used to construct the SQLite connection URL.
        database_path: String,
    },
    /// In-memory only — for tests.
    Memory,
}

impl StorageProfile {
    /// Build a [`Storage`] composite from this profile.
    pub async fn build(self) -> Result<Storage> {
        match self {
            StorageProfile::Lite { database_path } => {
                let url = format!("sqlite:{database_path}");
                // Share a single pool across trace + metadata repos
                let pool = sqlite::open_pool(&url).await?;
                let traces = Arc::new(SqliteTraceRepository::from_pool(pool.clone()).await?);
                let metadata = Arc::new(SqliteMetadataRepository::from_pool(pool).await?);
                let cache = Arc::new(InMemoryCacheLayer::new());
                Ok(Storage {
                    traces,
                    metadata,
                    cache,
                })
            }
            StorageProfile::Memory => Ok(Storage {
                traces: Arc::new(InMemoryTraceRepository::new()),
                metadata: Arc::new(InMemoryMetadataRepository::new()),
                cache: Arc::new(InMemoryCacheLayer::new()),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use llmtrace_core::{LLMProvider, Tenant, TenantId, TraceEvent, TraceQuery, TraceSpan};
    use std::time::Duration;
    use uuid::Uuid;

    fn make_trace(tenant_id: TenantId) -> TraceEvent {
        let trace_id = Uuid::new_v4();
        TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![TraceSpan::new(
                trace_id,
                tenant_id,
                "chat_completion".to_string(),
                LLMProvider::OpenAI,
                "gpt-4".to_string(),
                "hello".to_string(),
            )],
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_storage_profile_memory() {
        let storage = StorageProfile::Memory.build().await.unwrap();

        // Traces
        let tenant = TenantId::new();
        storage
            .traces
            .store_trace(&make_trace(tenant))
            .await
            .unwrap();
        let traces = storage
            .traces
            .query_traces(&TraceQuery::new(tenant))
            .await
            .unwrap();
        assert_eq!(traces.len(), 1);

        // Metadata
        let t = Tenant {
            id: tenant,
            name: "Test".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        storage.metadata.create_tenant(&t).await.unwrap();
        let retrieved = storage.metadata.get_tenant(tenant).await.unwrap();
        assert!(retrieved.is_some());

        // Cache
        storage
            .cache
            .set("k", b"v", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(storage.cache.get("k").await.unwrap(), Some(b"v".to_vec()));
    }

    #[tokio::test]
    async fn test_storage_profile_lite() {
        // Use a temp file for the SQLite database
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db").to_string_lossy().to_string();

        let storage = StorageProfile::Lite {
            database_path: db_path,
        }
        .build()
        .await
        .unwrap();

        let tenant = TenantId::new();
        storage
            .traces
            .store_trace(&make_trace(tenant))
            .await
            .unwrap();
        let traces = storage
            .traces
            .query_traces(&TraceQuery::new(tenant))
            .await
            .unwrap();
        assert_eq!(traces.len(), 1);

        // Metadata works on the same pool
        let t = Tenant {
            id: tenant,
            name: "LiteTenant".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        storage.metadata.create_tenant(&t).await.unwrap();
        let retrieved = storage.metadata.get_tenant(tenant).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "LiteTenant");

        // Health checks
        assert!(storage.traces.health_check().await.is_ok());
        assert!(storage.metadata.health_check().await.is_ok());
        assert!(storage.cache.health_check().await.is_ok());
    }
}
