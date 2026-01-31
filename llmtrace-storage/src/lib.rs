//! Storage abstraction layer for LLMTrace
//!
//! This crate provides storage backends for persisting traces and security events.

use async_trait::async_trait;
use llmtrace_core::{LLMTraceError, Result, StorageBackend, TenantId, TraceEvent};
use sqlx::{Row, SqlitePool};

/// SQLite storage backend implementation
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Create a new SQLite storage backend
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to connect to SQLite: {}", e)))?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    /// Run database migrations
    async fn run_migrations(&self) -> Result<()> {
        // TODO: Implement proper migrations in Loop 2
        // For now, just create a simple table structure
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS traces (
                id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                trace_data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Migration failed: {}", e)))?;

        Ok(())
    }
}

#[async_trait]
impl StorageBackend for SqliteStorage {
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()> {
        let trace_json = serde_json::to_string(trace)
            .map_err(|e| LLMTraceError::Storage(format!("Failed to serialize trace: {}", e)))?;

        sqlx::query("INSERT INTO traces (id, tenant_id, trace_data) VALUES (?1, ?2, ?3)")
            .bind(trace.trace_id.to_string())
            .bind(trace.tenant_id.0.to_string())
            .bind(trace_json)
            .execute(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to insert trace: {}", e)))?;

        Ok(())
    }

    async fn query_traces(
        &self,
        tenant_id: TenantId,
        limit: Option<u32>,
    ) -> Result<Vec<TraceEvent>> {
        let limit_clause = limit.map(|l| format!(" LIMIT {}", l)).unwrap_or_default();
        let query_str = format!(
            "SELECT trace_data FROM traces WHERE tenant_id = ?1 ORDER BY created_at DESC{}",
            limit_clause
        );

        let rows = sqlx::query(&query_str)
            .bind(tenant_id.0.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query traces: {}", e)))?;

        let mut traces = Vec::new();
        for row in rows {
            let trace_data: String = row.get("trace_data");
            let trace: TraceEvent = serde_json::from_str(&trace_data).map_err(|e| {
                LLMTraceError::Storage(format!("Failed to deserialize trace: {}", e))
            })?;
            traces.push(trace);
        }

        Ok(traces)
    }

    async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Health check failed: {}", e)))?;

        Ok(())
    }
}

/// In-memory storage backend for testing
pub struct InMemoryStorage {
    traces: tokio::sync::RwLock<Vec<TraceEvent>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            traces: tokio::sync::RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for InMemoryStorage {
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()> {
        let mut traces = self.traces.write().await;
        traces.push(trace.clone());
        Ok(())
    }

    async fn query_traces(
        &self,
        tenant_id: TenantId,
        limit: Option<u32>,
    ) -> Result<Vec<TraceEvent>> {
        let traces = self.traces.read().await;
        let mut filtered: Vec<TraceEvent> = traces
            .iter()
            .filter(|t| t.tenant_id == tenant_id)
            .cloned()
            .collect();

        filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        if let Some(limit) = limit {
            filtered.truncate(limit as usize);
        }

        Ok(filtered)
    }

    async fn health_check(&self) -> Result<()> {
        // In-memory storage is always healthy
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use llmtrace_core::{TenantId, TraceEvent};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryStorage::new();
        let tenant_id = TenantId::new();

        let trace = TraceEvent {
            trace_id: Uuid::new_v4(),
            tenant_id,
            spans: vec![],
            created_at: Utc::now(),
        };

        // Test store and query
        storage.store_trace(&trace).await.unwrap();
        let traces = storage.query_traces(tenant_id, None).await.unwrap();

        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].trace_id, trace.trace_id);
    }

    #[tokio::test]
    async fn test_health_check() {
        let storage = InMemoryStorage::new();
        assert!(storage.health_check().await.is_ok());
    }
}
