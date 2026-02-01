//! In-memory storage backends for testing.
//!
//! Stores all data in memory. Not intended for production use.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use llmtrace_core::{
    AuditEvent, AuditQuery, LLMTraceError, MetadataRepository, Result, StorageStats, Tenant,
    TenantConfig, TenantId, TraceEvent, TraceQuery, TraceRepository, TraceSpan,
};
use tokio::sync::RwLock;
use uuid::Uuid;

// ===========================================================================
// InMemoryTraceRepository
// ===========================================================================

/// In-memory trace repository for testing.
///
/// Data is lost when the struct is dropped. All methods are `O(n)` linear scans.
pub struct InMemoryTraceRepository {
    traces: RwLock<Vec<TraceEvent>>,
    /// Spans stored via [`TraceRepository::store_span`] outside of a full trace.
    standalone_spans: RwLock<Vec<TraceSpan>>,
}

impl InMemoryTraceRepository {
    /// Create a new, empty in-memory trace repository.
    pub fn new() -> Self {
        Self {
            traces: RwLock::new(Vec::new()),
            standalone_spans: RwLock::new(Vec::new()),
        }
    }

    /// Collect all spans for a given tenant from both traces and standalone storage.
    async fn all_spans_for_tenant(&self, tenant_id: TenantId) -> Vec<TraceSpan> {
        let traces = self.traces.read().await;
        let standalone = self.standalone_spans.read().await;

        let mut out: Vec<TraceSpan> = traces
            .iter()
            .filter(|t| t.tenant_id == tenant_id)
            .flat_map(|t| t.spans.iter().cloned())
            .collect();

        out.extend(
            standalone
                .iter()
                .filter(|s| s.tenant_id == tenant_id)
                .cloned(),
        );

        out
    }

    /// Check whether a span matches the non-tenant filters in a [`TraceQuery`].
    fn span_matches(span: &TraceSpan, query: &TraceQuery) -> bool {
        if let Some(ref start) = query.start_time {
            if span.start_time < *start {
                return false;
            }
        }
        if let Some(ref end) = query.end_time {
            if span.start_time > *end {
                return false;
            }
        }
        if let Some(ref provider) = query.provider {
            if span.provider != *provider {
                return false;
            }
        }
        if let Some(ref model) = query.model_name {
            if span.model_name != *model {
                return false;
            }
        }
        if let Some(ref op) = query.operation_name {
            if span.operation_name != *op {
                return false;
            }
        }
        if let Some(min) = query.min_security_score {
            match span.security_score {
                Some(score) if score >= min => {}
                _ => return false,
            }
        }
        if let Some(max) = query.max_security_score {
            match span.security_score {
                Some(score) if score <= max => {}
                _ => return false,
            }
        }
        if let Some(ref trace_id) = query.trace_id {
            if span.trace_id != *trace_id {
                return false;
            }
        }
        true
    }
}

impl Default for InMemoryTraceRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TraceRepository for InMemoryTraceRepository {
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()> {
        let mut traces = self.traces.write().await;
        traces.retain(|t| !(t.tenant_id == trace.tenant_id && t.trace_id == trace.trace_id));
        traces.push(trace.clone());
        Ok(())
    }

    async fn store_span(&self, span: &TraceSpan) -> Result<()> {
        let mut standalone = self.standalone_spans.write().await;
        standalone.retain(|s| !(s.tenant_id == span.tenant_id && s.span_id == span.span_id));
        standalone.push(span.clone());
        Ok(())
    }

    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>> {
        let all_spans = self.all_spans_for_tenant(query.tenant_id).await;

        let mut matching_trace_ids: Vec<Uuid> = all_spans
            .iter()
            .filter(|s| Self::span_matches(s, query))
            .map(|s| s.trace_id)
            .collect();
        matching_trace_ids.sort();
        matching_trace_ids.dedup();

        let traces = self.traces.read().await;
        let standalone = self.standalone_spans.read().await;

        let mut results: Vec<TraceEvent> = Vec::new();
        for tid in &matching_trace_ids {
            if let Some(t) = traces
                .iter()
                .find(|t| t.tenant_id == query.tenant_id && t.trace_id == *tid)
            {
                results.push(t.clone());
            } else {
                let spans: Vec<TraceSpan> = standalone
                    .iter()
                    .filter(|s| s.tenant_id == query.tenant_id && s.trace_id == *tid)
                    .cloned()
                    .collect();
                if !spans.is_empty() {
                    let created_at = spans
                        .iter()
                        .map(|s| s.start_time)
                        .min()
                        .unwrap_or_else(Utc::now);
                    results.push(TraceEvent {
                        trace_id: *tid,
                        tenant_id: query.tenant_id,
                        spans,
                        created_at,
                    });
                }
            }
        }

        results.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        if let Some(offset) = query.offset {
            let offset = offset as usize;
            if offset < results.len() {
                results = results.split_off(offset);
            } else {
                results.clear();
            }
        }
        if let Some(limit) = query.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
    }

    async fn query_spans(&self, query: &TraceQuery) -> Result<Vec<TraceSpan>> {
        let mut all = self.all_spans_for_tenant(query.tenant_id).await;
        all.retain(|s| Self::span_matches(s, query));
        all.sort_by(|a, b| b.start_time.cmp(&a.start_time));

        if let Some(offset) = query.offset {
            let offset = offset as usize;
            if offset < all.len() {
                all = all.split_off(offset);
            } else {
                all.clear();
            }
        }
        if let Some(limit) = query.limit {
            all.truncate(limit as usize);
        }

        Ok(all)
    }

    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>> {
        let traces = self.traces.read().await;
        let trace = traces
            .iter()
            .find(|t| t.tenant_id == tenant_id && t.trace_id == trace_id)
            .cloned();
        Ok(trace)
    }

    async fn get_span(&self, tenant_id: TenantId, span_id: Uuid) -> Result<Option<TraceSpan>> {
        let traces = self.traces.read().await;
        for trace in traces.iter() {
            if trace.tenant_id != tenant_id {
                continue;
            }
            if let Some(span) = trace.spans.iter().find(|s| s.span_id == span_id) {
                return Ok(Some(span.clone()));
            }
        }
        drop(traces);

        let standalone = self.standalone_spans.read().await;
        let span = standalone
            .iter()
            .find(|s| s.tenant_id == tenant_id && s.span_id == span_id)
            .cloned();
        Ok(span)
    }

    async fn delete_traces_before(
        &self,
        tenant_id: TenantId,
        before: DateTime<Utc>,
    ) -> Result<u64> {
        let mut traces = self.traces.write().await;
        let initial = traces.len();
        traces.retain(|t| !(t.tenant_id == tenant_id && t.created_at < before));
        let deleted = initial - traces.len();

        let mut standalone = self.standalone_spans.write().await;
        standalone.retain(|s| !(s.tenant_id == tenant_id && s.start_time < before));

        Ok(deleted as u64)
    }

    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats> {
        let traces = self.traces.read().await;
        let standalone = self.standalone_spans.read().await;

        let tenant_traces: Vec<_> = traces.iter().filter(|t| t.tenant_id == tenant_id).collect();
        let total_traces = tenant_traces.len() as u64;

        let trace_span_count: usize = tenant_traces.iter().map(|t| t.spans.len()).sum();
        let standalone_span_count = standalone
            .iter()
            .filter(|s| s.tenant_id == tenant_id)
            .count();
        let total_spans = (trace_span_count + standalone_span_count) as u64;

        let oldest_trace = tenant_traces.iter().map(|t| t.created_at).min();
        let newest_trace = tenant_traces.iter().map(|t| t.created_at).max();

        Ok(StorageStats {
            total_traces,
            total_spans,
            storage_size_bytes: 0,
            oldest_trace,
            newest_trace,
        })
    }

    async fn health_check(&self) -> Result<()> {
        Ok(())
    }
}

// ===========================================================================
// InMemoryMetadataRepository
// ===========================================================================

/// In-memory metadata repository for testing.
pub struct InMemoryMetadataRepository {
    tenants: RwLock<Vec<Tenant>>,
    configs: RwLock<Vec<TenantConfig>>,
    audit_events: RwLock<Vec<AuditEvent>>,
}

impl InMemoryMetadataRepository {
    /// Create a new, empty in-memory metadata repository.
    pub fn new() -> Self {
        Self {
            tenants: RwLock::new(Vec::new()),
            configs: RwLock::new(Vec::new()),
            audit_events: RwLock::new(Vec::new()),
        }
    }
}

impl Default for InMemoryMetadataRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MetadataRepository for InMemoryMetadataRepository {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        if tenants.iter().any(|t| t.id == tenant.id) {
            return Err(LLMTraceError::Storage(format!(
                "Tenant {} already exists",
                tenant.id
            )));
        }
        tenants.push(tenant.clone());
        Ok(())
    }

    async fn get_tenant(&self, id: TenantId) -> Result<Option<Tenant>> {
        let tenants = self.tenants.read().await;
        Ok(tenants.iter().find(|t| t.id == id).cloned())
    }

    async fn update_tenant(&self, tenant: &Tenant) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        if let Some(existing) = tenants.iter_mut().find(|t| t.id == tenant.id) {
            *existing = tenant.clone();
            Ok(())
        } else {
            Err(LLMTraceError::InvalidTenant {
                tenant_id: tenant.id,
            })
        }
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let tenants = self.tenants.read().await;
        Ok(tenants.clone())
    }

    async fn delete_tenant(&self, id: TenantId) -> Result<()> {
        let mut tenants = self.tenants.write().await;
        tenants.retain(|t| t.id != id);
        Ok(())
    }

    async fn get_tenant_config(&self, tenant_id: TenantId) -> Result<Option<TenantConfig>> {
        let configs = self.configs.read().await;
        Ok(configs.iter().find(|c| c.tenant_id == tenant_id).cloned())
    }

    async fn upsert_tenant_config(&self, config: &TenantConfig) -> Result<()> {
        let mut configs = self.configs.write().await;
        configs.retain(|c| c.tenant_id != config.tenant_id);
        configs.push(config.clone());
        Ok(())
    }

    async fn record_audit_event(&self, event: &AuditEvent) -> Result<()> {
        let mut events = self.audit_events.write().await;
        events.push(event.clone());
        Ok(())
    }

    async fn query_audit_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let events = self.audit_events.read().await;
        let mut results: Vec<_> = events
            .iter()
            .filter(|e| {
                if e.tenant_id != query.tenant_id {
                    return false;
                }
                if let Some(ref et) = query.event_type {
                    if e.event_type != *et {
                        return false;
                    }
                }
                if let Some(ref start) = query.start_time {
                    if e.timestamp < *start {
                        return false;
                    }
                }
                if let Some(ref end) = query.end_time {
                    if e.timestamp > *end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(offset) = query.offset {
            let offset = offset as usize;
            if offset < results.len() {
                results = results.split_off(offset);
            } else {
                results.clear();
            }
        }
        if let Some(limit) = query.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
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
    use llmtrace_core::{LLMProvider, TenantId, TraceEvent, TraceQuery, TraceSpan};
    use uuid::Uuid;

    fn make_span(trace_id: Uuid, tenant_id: TenantId) -> TraceSpan {
        TraceSpan::new(
            trace_id,
            tenant_id,
            "chat_completion".to_string(),
            LLMProvider::OpenAI,
            "gpt-4".to_string(),
            "test prompt".to_string(),
        )
    }

    fn make_trace(tenant_id: TenantId) -> TraceEvent {
        let trace_id = Uuid::new_v4();
        TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![make_span(trace_id, tenant_id)],
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_in_memory_store_and_retrieve() {
        let storage = InMemoryTraceRepository::new();
        let tenant = TenantId::new();
        let trace = make_trace(tenant);

        storage.store_trace(&trace).await.unwrap();

        let query = TraceQuery::new(tenant);
        let results = storage.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, trace.trace_id);
    }

    #[tokio::test]
    async fn test_in_memory_store_span() {
        let storage = InMemoryTraceRepository::new();
        let tenant = TenantId::new();
        let trace_id = Uuid::new_v4();
        let span = make_span(trace_id, tenant);

        storage.store_span(&span).await.unwrap();

        let retrieved = storage
            .get_span(tenant, span.span_id)
            .await
            .unwrap()
            .expect("span should exist");
        assert_eq!(retrieved.span_id, span.span_id);
    }

    #[tokio::test]
    async fn test_in_memory_tenant_isolation() {
        let storage = InMemoryTraceRepository::new();
        let t1 = TenantId::new();
        let t2 = TenantId::new();

        storage.store_trace(&make_trace(t1)).await.unwrap();
        storage.store_trace(&make_trace(t2)).await.unwrap();

        let r1 = storage.query_traces(&TraceQuery::new(t1)).await.unwrap();
        assert_eq!(r1.len(), 1);
        assert_eq!(r1[0].tenant_id, t1);
    }

    #[tokio::test]
    async fn test_in_memory_health_check() {
        let storage = InMemoryTraceRepository::new();
        assert!(storage.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_in_memory_get_stats() {
        let storage = InMemoryTraceRepository::new();
        let tenant = TenantId::new();

        storage.store_trace(&make_trace(tenant)).await.unwrap();
        storage.store_trace(&make_trace(tenant)).await.unwrap();

        let stats = storage.get_stats(tenant).await.unwrap();
        assert_eq!(stats.total_traces, 2);
        assert_eq!(stats.total_spans, 2);
    }

    #[tokio::test]
    async fn test_in_memory_delete_before() {
        let storage = InMemoryTraceRepository::new();
        let tenant = TenantId::new();

        let old = TraceEvent {
            trace_id: Uuid::new_v4(),
            tenant_id: tenant,
            spans: vec![],
            created_at: Utc::now() - chrono::Duration::hours(2),
        };
        let new = make_trace(tenant);

        storage.store_trace(&old).await.unwrap();
        storage.store_trace(&new).await.unwrap();

        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let deleted = storage.delete_traces_before(tenant, cutoff).await.unwrap();
        assert_eq!(deleted, 1);

        let remaining = storage
            .query_traces(&TraceQuery::new(tenant))
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
    }

    // -- In-memory metadata tests ------------------------------------------

    #[tokio::test]
    async fn test_in_memory_metadata_tenant_crud() {
        let repo = InMemoryMetadataRepository::new();
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Test".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };

        repo.create_tenant(&tenant).await.unwrap();
        let retrieved = repo.get_tenant(tenant.id).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Test");

        let mut updated = tenant.clone();
        updated.name = "Updated".to_string();
        repo.update_tenant(&updated).await.unwrap();
        let after = repo.get_tenant(tenant.id).await.unwrap().unwrap();
        assert_eq!(after.name, "Updated");

        repo.delete_tenant(tenant.id).await.unwrap();
        assert!(repo.get_tenant(tenant.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_in_memory_metadata_health() {
        let repo = InMemoryMetadataRepository::new();
        assert!(repo.health_check().await.is_ok());
    }
}
