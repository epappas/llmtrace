//! Storage abstraction layer for LLMTrace
//!
//! This crate provides storage backends for persisting traces and security events.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use llmtrace_core::{
    LLMTraceError, Result, StorageBackend, StorageStats, TenantId, TraceEvent, TraceQuery,
    TraceSpan,
};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

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

    async fn store_span(&self, _span: &TraceSpan) -> Result<()> {
        // TODO: Implement span storage in Loop 2
        Ok(())
    }

    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>> {
        let limit_clause = query
            .limit
            .map(|l| format!(" LIMIT {}", l))
            .unwrap_or_default();
        let query_str = format!(
            "SELECT trace_data FROM traces WHERE tenant_id = ?1 ORDER BY created_at DESC{}",
            limit_clause
        );

        let rows = sqlx::query(&query_str)
            .bind(query.tenant_id.0.to_string())
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

    async fn query_spans(&self, _query: &TraceQuery) -> Result<Vec<TraceSpan>> {
        // TODO: Implement span querying in Loop 2
        Ok(vec![])
    }

    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>> {
        let row = sqlx::query("SELECT trace_data FROM traces WHERE tenant_id = ?1 AND id = ?2")
            .bind(tenant_id.0.to_string())
            .bind(trace_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get trace: {}", e)))?;

        if let Some(row) = row {
            let trace_data: String = row.get("trace_data");
            let trace: TraceEvent = serde_json::from_str(&trace_data).map_err(|e| {
                LLMTraceError::Storage(format!("Failed to deserialize trace: {}", e))
            })?;
            Ok(Some(trace))
        } else {
            Ok(None)
        }
    }

    async fn get_span(&self, _tenant_id: TenantId, _span_id: Uuid) -> Result<Option<TraceSpan>> {
        // TODO: Implement span retrieval in Loop 2
        Ok(None)
    }

    async fn delete_traces_before(
        &self,
        tenant_id: TenantId,
        before: DateTime<Utc>,
    ) -> Result<u64> {
        let result = sqlx::query("DELETE FROM traces WHERE tenant_id = ?1 AND created_at < ?2")
            .bind(tenant_id.0.to_string())
            .bind(before)
            .execute(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to delete traces: {}", e)))?;

        Ok(result.rows_affected())
    }

    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats> {
        let count_row = sqlx::query("SELECT COUNT(*) as count FROM traces WHERE tenant_id = ?1")
            .bind(tenant_id.0.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get count: {}", e)))?;

        let total_traces: i64 = count_row.get("count");

        // TODO: Implement proper storage size calculation
        Ok(StorageStats {
            total_traces: total_traces as u64,
            total_spans: 0,        // TODO: Calculate from spans table
            storage_size_bytes: 0, // TODO: Calculate actual size
            oldest_trace: None,    // TODO: Query for oldest
            newest_trace: None,    // TODO: Query for newest
        })
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

    async fn store_span(&self, _span: &TraceSpan) -> Result<()> {
        // TODO: Implement span storage
        Ok(())
    }

    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>> {
        let traces = self.traces.read().await;
        let mut filtered: Vec<TraceEvent> = traces
            .iter()
            .filter(|t| t.tenant_id == query.tenant_id)
            .cloned()
            .collect();

        filtered.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        if let Some(limit) = query.limit {
            filtered.truncate(limit as usize);
        }

        Ok(filtered)
    }

    async fn query_spans(&self, _query: &TraceQuery) -> Result<Vec<TraceSpan>> {
        // TODO: Implement span querying
        Ok(vec![])
    }

    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>> {
        let traces = self.traces.read().await;
        let trace = traces
            .iter()
            .find(|t| t.tenant_id == tenant_id && t.trace_id == trace_id)
            .cloned();
        Ok(trace)
    }

    async fn get_span(&self, _tenant_id: TenantId, _span_id: Uuid) -> Result<Option<TraceSpan>> {
        // TODO: Implement span retrieval
        Ok(None)
    }

    async fn delete_traces_before(
        &self,
        tenant_id: TenantId,
        before: DateTime<Utc>,
    ) -> Result<u64> {
        let mut traces = self.traces.write().await;
        let initial_len = traces.len();
        traces.retain(|t| t.tenant_id != tenant_id || t.created_at >= before);
        let deleted = initial_len - traces.len();
        Ok(deleted as u64)
    }

    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats> {
        let traces = self.traces.read().await;
        let tenant_traces: Vec<_> = traces.iter().filter(|t| t.tenant_id == tenant_id).collect();

        let total_traces = tenant_traces.len() as u64;
        let oldest_trace = tenant_traces.iter().map(|t| t.created_at).min();
        let newest_trace = tenant_traces.iter().map(|t| t.created_at).max();

        Ok(StorageStats {
            total_traces,
            total_spans: 0,        // TODO: Calculate from spans
            storage_size_bytes: 0, // TODO: Estimate memory usage
            oldest_trace,
            newest_trace,
        })
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
    use llmtrace_core::{TenantId, TraceEvent, TraceQuery};
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
        let query = TraceQuery::new(tenant_id);
        let traces = storage.query_traces(&query).await.unwrap();

        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].trace_id, trace.trace_id);
    }

    #[tokio::test]
    async fn test_health_check() {
        let storage = InMemoryStorage::new();
        assert!(storage.health_check().await.is_ok());
    }
}
