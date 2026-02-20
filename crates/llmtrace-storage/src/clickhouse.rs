//! ClickHouse storage backend for trace and span data.
//!
//! Provides [`ClickHouseTraceRepository`] — a high-throughput, columnar-storage
//! backed implementation of [`TraceRepository`] suitable for production analytical
//! workloads.
//!
//! Gated behind the `clickhouse` Cargo feature.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clickhouse::Client;
use llmtrace_core::{
    AgentAction, LLMProvider, LLMTraceError, Result, SecurityFinding, SpanEvent, StorageStats,
    TenantId, TraceEvent, TraceQuery, TraceRepository, TraceSpan,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Row types for ClickHouse serialization
// ---------------------------------------------------------------------------

/// Row type for the `traces` table.
#[derive(Debug, clickhouse::Row, Serialize, Deserialize)]
struct TraceRow {
    #[serde(with = "clickhouse::serde::uuid")]
    trace_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    tenant_id: Uuid,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    created_at: DateTime<Utc>,
}

/// Row type for the `spans` table.
#[derive(Debug, clickhouse::Row, Serialize, Deserialize)]
struct SpanRow {
    #[serde(with = "clickhouse::serde::uuid")]
    tenant_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    trace_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    span_id: Uuid,
    #[serde(with = "clickhouse::serde::uuid::option")]
    parent_span_id: Option<Uuid>,
    operation_name: String,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    start_time: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis::option")]
    end_time: Option<DateTime<Utc>>,
    duration_ms: Option<u64>,
    provider: String,
    model_name: String,
    prompt: String,
    response: Option<String>,
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    total_tokens: Option<u32>,
    time_to_first_token_ms: Option<u64>,
    status_code: Option<u16>,
    error_message: Option<String>,
    estimated_cost_usd: Option<f64>,
    security_score: Option<u8>,
    security_findings: String,
    tags: String,
    events: String,
    agent_actions: String,
}

/// Row type returned by the count query used in [`ClickHouseTraceRepository::get_stats`].
#[derive(Debug, clickhouse::Row, Deserialize)]
struct CountRow {
    cnt: u64,
}

/// Row type for approximate storage size estimation.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct SizeRow {
    sz: u64,
}

/// Row type for time-range queries on the traces table.
///
/// Uses non-optional `DateTime64(3)` fields because ClickHouse's `min`/`max`
/// aggregate functions return a non-nullable `DateTime64(3)`.  The caller
/// should only execute this query when at least one row exists.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct TimeRangeRow {
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    oldest: DateTime<Utc>,
    #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
    newest: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Serialize an [`LLMProvider`] for storage as a String column.
fn serialize_provider(provider: &LLMProvider) -> String {
    serde_json::to_string(provider).expect("LLMProvider serialization cannot fail")
}

/// Deserialize an [`LLMProvider`] from its stored String representation.
fn deserialize_provider(s: &str) -> Result<LLMProvider> {
    serde_json::from_str(s)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid provider value '{s}': {e}")))
}

/// Escape a string for safe use inside a ClickHouse single-quoted literal.
fn escape_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Format a UUID as a ClickHouse-safe quoted literal.
fn fmt_uuid(id: &Uuid) -> String {
    // UUIDs contain only hex digits and dashes — always safe.
    format!("'{id}'")
}

/// Format a [`DateTime<Utc>`] as a ClickHouse-safe quoted literal.
fn fmt_datetime(dt: &DateTime<Utc>) -> String {
    format!("'{}'", dt.format("%Y-%m-%d %H:%M:%S%.3f"))
}

/// Format a string value as a ClickHouse-safe quoted literal.
fn fmt_string(s: &str) -> String {
    format!("'{}'", escape_string(s))
}

// ---------------------------------------------------------------------------
// Domain ↔ Row conversions
// ---------------------------------------------------------------------------

/// Convert a [`TraceSpan`] into a [`SpanRow`] for ClickHouse insertion.
fn span_to_row(span: &TraceSpan) -> Result<SpanRow> {
    let security_findings_json = serde_json::to_string(&span.security_findings)
        .map_err(|e| LLMTraceError::Storage(format!("serialize security_findings: {e}")))?;
    let tags_json = serde_json::to_string(&span.tags)
        .map_err(|e| LLMTraceError::Storage(format!("serialize tags: {e}")))?;
    let events_json = serde_json::to_string(&span.events)
        .map_err(|e| LLMTraceError::Storage(format!("serialize events: {e}")))?;
    let agent_actions_json = serde_json::to_string(&span.agent_actions)
        .map_err(|e| LLMTraceError::Storage(format!("serialize agent_actions: {e}")))?;

    Ok(SpanRow {
        tenant_id: span.tenant_id.0,
        trace_id: span.trace_id,
        span_id: span.span_id,
        parent_span_id: span.parent_span_id,
        operation_name: span.operation_name.clone(),
        start_time: span.start_time,
        end_time: span.end_time,
        duration_ms: span.duration_ms,
        provider: serialize_provider(&span.provider),
        model_name: span.model_name.clone(),
        prompt: span.prompt.clone(),
        response: span.response.clone(),
        prompt_tokens: span.prompt_tokens,
        completion_tokens: span.completion_tokens,
        total_tokens: span.total_tokens,
        time_to_first_token_ms: span.time_to_first_token_ms,
        status_code: span.status_code,
        error_message: span.error_message.clone(),
        estimated_cost_usd: span.estimated_cost_usd,
        security_score: span.security_score,
        security_findings: security_findings_json,
        tags: tags_json,
        events: events_json,
        agent_actions: agent_actions_json,
    })
}

/// Convert a [`SpanRow`] back into a [`TraceSpan`].
fn row_to_span(row: SpanRow) -> Result<TraceSpan> {
    let security_findings: Vec<SecurityFinding> = serde_json::from_str(&row.security_findings)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid security_findings JSON: {e}")))?;
    let tags: HashMap<String, String> = serde_json::from_str(&row.tags)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid tags JSON: {e}")))?;
    let events: Vec<SpanEvent> = serde_json::from_str(&row.events)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid events JSON: {e}")))?;
    let agent_actions: Vec<AgentAction> = serde_json::from_str(&row.agent_actions)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid agent_actions JSON: {e}")))?;

    Ok(TraceSpan {
        trace_id: row.trace_id,
        span_id: row.span_id,
        parent_span_id: row.parent_span_id,
        tenant_id: TenantId(row.tenant_id),
        operation_name: row.operation_name,
        start_time: row.start_time,
        end_time: row.end_time,
        provider: deserialize_provider(&row.provider)?,
        model_name: row.model_name,
        prompt: row.prompt,
        response: row.response,
        prompt_tokens: row.prompt_tokens,
        completion_tokens: row.completion_tokens,
        total_tokens: row.total_tokens,
        time_to_first_token_ms: row.time_to_first_token_ms,
        duration_ms: row.duration_ms,
        status_code: row.status_code,
        error_message: row.error_message,
        estimated_cost_usd: row.estimated_cost_usd,
        security_score: row.security_score,
        security_findings,
        tags,
        events,
        agent_actions,
    })
}

// ===========================================================================
// ClickHouseTraceRepository
// ===========================================================================

/// ClickHouse-backed trace repository for production analytical workloads.
///
/// Stores trace metadata in a `traces` table and individual spans in a `spans`
/// table using the MergeTree engine, partitioned by tenant and month for
/// efficient range queries and data lifecycle management.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> llmtrace_core::Result<()> {
/// use llmtrace_core::TraceRepository;
/// let repo = llmtrace_storage::ClickHouseTraceRepository::new(
///     "http://localhost:8123",
///     "llmtrace",
/// ).await?;
/// repo.health_check().await?;
/// # Ok(())
/// # }
/// ```
pub struct ClickHouseTraceRepository {
    client: Client,
    database: String,
}

impl ClickHouseTraceRepository {
    /// Create a new ClickHouse trace repository.
    ///
    /// Connects to the given ClickHouse HTTP URL and ensures the database,
    /// `traces` table, and `spans` table exist (creating them if necessary).
    pub async fn new(url: &str, database: &str) -> Result<Self> {
        let base_client = Client::default().with_url(url);

        // Create the database first (without setting it as the default).
        base_client
            .query(&format!("CREATE DATABASE IF NOT EXISTS `{database}`"))
            .execute()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to create database: {e}")))?;

        // Now create a client that targets the database.
        let client = base_client.with_database(database);

        let repo = Self {
            client,
            database: database.to_string(),
        };
        repo.run_migrations().await?;
        Ok(repo)
    }

    /// Run DDL migrations to create the required tables.
    async fn run_migrations(&self) -> Result<()> {
        let db = &self.database;

        self.client
            .query(&format!(
                "CREATE TABLE IF NOT EXISTS `{db}`.traces (
                    trace_id UUID,
                    tenant_id UUID,
                    created_at DateTime64(3)
                ) ENGINE = MergeTree()
                PARTITION BY (tenant_id, toYYYYMM(created_at))
                ORDER BY (tenant_id, created_at, trace_id)"
            ))
            .execute()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to create traces table: {e}")))?;

        self.client
            .query(&format!(
                "CREATE TABLE IF NOT EXISTS `{db}`.spans (
                    tenant_id UUID,
                    trace_id UUID,
                    span_id UUID,
                    parent_span_id Nullable(UUID),
                    operation_name LowCardinality(String),
                    start_time DateTime64(3),
                    end_time Nullable(DateTime64(3)),
                    duration_ms Nullable(UInt64),
                    provider LowCardinality(String),
                    model_name LowCardinality(String),
                    prompt String CODEC(ZSTD(1)),
                    response Nullable(String) CODEC(ZSTD(1)),
                    prompt_tokens Nullable(UInt32),
                    completion_tokens Nullable(UInt32),
                    total_tokens Nullable(UInt32),
                    time_to_first_token_ms Nullable(UInt64),
                    status_code Nullable(UInt16),
                    error_message Nullable(String),
                    estimated_cost_usd Nullable(Float64),
                    security_score Nullable(UInt8),
                    security_findings String DEFAULT '[]',
                    tags String DEFAULT '{{}}',
                    events String DEFAULT '[]',
                    agent_actions String DEFAULT '[]' CODEC(ZSTD(1))
                ) ENGINE = MergeTree()
                PARTITION BY (tenant_id, toYYYYMM(start_time))
                ORDER BY (tenant_id, start_time, trace_id, span_id)"
            ))
            .execute()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to create spans table: {e}")))?;

        // Migration: add agent_actions column to existing spans tables
        let _ = self
            .client
            .query(&format!(
                "ALTER TABLE `{db}`.spans ADD COLUMN IF NOT EXISTS \
                 agent_actions String DEFAULT '[]' CODEC(ZSTD(1))"
            ))
            .execute()
            .await;

        Ok(())
    }

    /// Build a dynamic WHERE clause from [`TraceQuery`] filters for the spans table.
    ///
    /// Returns the SQL fragment starting with `tenant_id = ...` (no leading `WHERE`).
    fn build_span_filter(query: &TraceQuery) -> String {
        let mut conditions = vec![format!("tenant_id = {}", fmt_uuid(&query.tenant_id.0))];

        if let Some(ref trace_id) = query.trace_id {
            conditions.push(format!("trace_id = {}", fmt_uuid(trace_id)));
        }
        if let Some(ref start) = query.start_time {
            conditions.push(format!("start_time >= {}", fmt_datetime(start)));
        }
        if let Some(ref end) = query.end_time {
            conditions.push(format!("start_time <= {}", fmt_datetime(end)));
        }
        if let Some(ref provider) = query.provider {
            conditions.push(format!(
                "provider = {}",
                fmt_string(&serialize_provider(provider))
            ));
        }
        if let Some(ref model) = query.model_name {
            conditions.push(format!("model_name = {}", fmt_string(model)));
        }
        if let Some(ref op) = query.operation_name {
            conditions.push(format!("operation_name = {}", fmt_string(op)));
        }
        if let Some(min) = query.min_security_score {
            conditions.push(format!("security_score >= {min}"));
        }
        if let Some(max) = query.max_security_score {
            conditions.push(format!("security_score <= {max}"));
        }

        conditions.join(" AND ")
    }

    /// Build the ORDER BY / LIMIT / OFFSET suffix for a query.
    fn build_pagination(query: &TraceQuery, order_col: &str) -> String {
        let mut sql = format!(" ORDER BY {order_col} DESC");
        if let Some(limit) = query.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        if let Some(offset) = query.offset {
            sql.push_str(&format!(" OFFSET {offset}"));
        }
        sql
    }
}

#[async_trait]
impl TraceRepository for ClickHouseTraceRepository {
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()> {
        // Insert trace metadata.
        let mut trace_insert = self
            .client
            .insert::<TraceRow>("traces")
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to prepare trace insert: {e}")))?;

        trace_insert
            .write(&TraceRow {
                trace_id: trace.trace_id,
                tenant_id: trace.tenant_id.0,
                created_at: trace.created_at,
            })
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to write trace row: {e}")))?;

        trace_insert
            .end()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to finish trace insert: {e}")))?;

        // Batch-insert spans.
        if !trace.spans.is_empty() {
            let mut span_insert = self.client.insert::<SpanRow>("spans").await.map_err(|e| {
                LLMTraceError::Storage(format!("Failed to prepare span insert: {e}"))
            })?;

            for span in &trace.spans {
                let row = span_to_row(span)?;
                span_insert.write(&row).await.map_err(|e| {
                    LLMTraceError::Storage(format!("Failed to write span row: {e}"))
                })?;
            }

            span_insert.end().await.map_err(|e| {
                LLMTraceError::Storage(format!("Failed to finish span insert: {e}"))
            })?;
        }

        Ok(())
    }

    async fn store_span(&self, span: &TraceSpan) -> Result<()> {
        // Ensure the parent trace row exists.
        let mut trace_insert = self
            .client
            .insert::<TraceRow>("traces")
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to prepare trace insert: {e}")))?;

        trace_insert
            .write(&TraceRow {
                trace_id: span.trace_id,
                tenant_id: span.tenant_id.0,
                created_at: span.start_time,
            })
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to write trace row: {e}")))?;

        trace_insert
            .end()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to finish trace insert: {e}")))?;

        // Insert the span.
        let mut span_insert =
            self.client.insert::<SpanRow>("spans").await.map_err(|e| {
                LLMTraceError::Storage(format!("Failed to prepare span insert: {e}"))
            })?;

        let row = span_to_row(span)?;
        span_insert
            .write(&row)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to write span row: {e}")))?;

        span_insert
            .end()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to finish span insert: {e}")))?;

        Ok(())
    }

    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>> {
        // Find matching trace IDs via the spans table.
        let filter = Self::build_span_filter(query);
        let pagination = Self::build_pagination(query, "t.created_at");

        let trace_id_sql = format!(
            "SELECT DISTINCT s.trace_id \
             FROM spans s \
             JOIN traces t ON s.trace_id = t.trace_id AND s.tenant_id = t.tenant_id \
             WHERE s.{filter}{pagination}"
        );

        #[derive(clickhouse::Row, Deserialize)]
        struct TraceIdRow {
            #[serde(with = "clickhouse::serde::uuid")]
            trace_id: Uuid,
        }

        let trace_ids: Vec<TraceIdRow> = self
            .client
            .query(&trace_id_sql)
            .fetch_all()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query trace IDs: {e}")))?;

        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }

        let id_list: String = trace_ids
            .iter()
            .map(|r| fmt_uuid(&r.trace_id))
            .collect::<Vec<_>>()
            .join(", ");

        let tenant_filter = fmt_uuid(&query.tenant_id.0);

        // Load trace metadata.
        let meta_sql = format!(
            "SELECT ?fields FROM traces \
             WHERE tenant_id = {tenant_filter} AND trace_id IN ({id_list}) \
             ORDER BY created_at DESC"
        );
        let meta_rows: Vec<TraceRow> = self
            .client
            .query(&meta_sql)
            .fetch_all()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to load trace metadata: {e}")))?;

        // Load all spans belonging to those traces.
        let span_sql = format!(
            "SELECT ?fields FROM spans \
             WHERE tenant_id = {tenant_filter} AND trace_id IN ({id_list}) \
             ORDER BY start_time ASC"
        );
        let span_rows: Vec<SpanRow> = self
            .client
            .query(&span_sql)
            .fetch_all()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to load spans: {e}")))?;

        // Group spans by trace_id.
        let mut grouped: HashMap<Uuid, Vec<TraceSpan>> = HashMap::new();
        for row in span_rows {
            let tid = row.trace_id;
            let span = row_to_span(row)?;
            grouped.entry(tid).or_default().push(span);
        }

        // Assemble results.
        let mut results = Vec::with_capacity(meta_rows.len());
        for meta in meta_rows {
            results.push(TraceEvent {
                trace_id: meta.trace_id,
                tenant_id: TenantId(meta.tenant_id),
                spans: grouped.remove(&meta.trace_id).unwrap_or_default(),
                created_at: meta.created_at,
            });
        }

        Ok(results)
    }

    async fn query_spans(&self, query: &TraceQuery) -> Result<Vec<TraceSpan>> {
        let filter = Self::build_span_filter(query);
        let pagination = Self::build_pagination(query, "start_time");

        let sql = format!("SELECT ?fields FROM spans WHERE {filter}{pagination}");

        let rows: Vec<SpanRow> = self
            .client
            .query(&sql)
            .fetch_all()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query spans: {e}")))?;

        rows.into_iter().map(row_to_span).collect()
    }

    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>> {
        let tid = fmt_uuid(&tenant_id.0);
        let trid = fmt_uuid(&trace_id);

        let meta_sql =
            format!("SELECT ?fields FROM traces WHERE tenant_id = {tid} AND trace_id = {trid}");
        let meta: Option<TraceRow> = self
            .client
            .query(&meta_sql)
            .fetch_optional()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get trace: {e}")))?;

        let Some(meta) = meta else {
            return Ok(None);
        };

        let span_sql = format!(
            "SELECT ?fields FROM spans \
             WHERE tenant_id = {tid} AND trace_id = {trid} \
             ORDER BY start_time ASC"
        );
        let span_rows: Vec<SpanRow> = self
            .client
            .query(&span_sql)
            .fetch_all()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to load trace spans: {e}")))?;

        let spans: Vec<TraceSpan> = span_rows
            .into_iter()
            .map(row_to_span)
            .collect::<Result<_>>()?;

        Ok(Some(TraceEvent {
            trace_id: meta.trace_id,
            tenant_id: TenantId(meta.tenant_id),
            spans,
            created_at: meta.created_at,
        }))
    }

    async fn get_span(&self, tenant_id: TenantId, span_id: Uuid) -> Result<Option<TraceSpan>> {
        let tid = fmt_uuid(&tenant_id.0);
        let sid = fmt_uuid(&span_id);

        let sql = format!("SELECT ?fields FROM spans WHERE tenant_id = {tid} AND span_id = {sid}");

        let row: Option<SpanRow> = self
            .client
            .query(&sql)
            .fetch_optional()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get span: {e}")))?;

        match row {
            Some(r) => Ok(Some(row_to_span(r)?)),
            None => Ok(None),
        }
    }

    async fn delete_traces_before(
        &self,
        tenant_id: TenantId,
        before: DateTime<Utc>,
    ) -> Result<u64> {
        let tid = fmt_uuid(&tenant_id.0);
        let before_str = fmt_datetime(&before);

        // Count traces that will be deleted.
        let count_sql = format!(
            "SELECT count() as cnt FROM traces \
             WHERE tenant_id = {tid} AND created_at < {before_str}"
        );
        let count_row: CountRow = self
            .client
            .query(&count_sql)
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to count traces: {e}")))?;

        let deleted = count_row.cnt;

        if deleted > 0 {
            // Delete matching spans.
            let delete_spans = format!(
                "ALTER TABLE `{}`.spans DELETE \
                 WHERE tenant_id = {tid} AND trace_id IN (\
                     SELECT trace_id FROM `{}`.traces \
                     WHERE tenant_id = {tid} AND created_at < {before_str}\
                 )",
                self.database, self.database
            );
            self.client
                .query(&delete_spans)
                .execute()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to delete spans: {e}")))?;

            // Delete matching traces.
            let delete_traces = format!(
                "ALTER TABLE `{}`.traces DELETE \
                 WHERE tenant_id = {tid} AND created_at < {before_str}",
                self.database
            );
            self.client
                .query(&delete_traces)
                .execute()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to delete traces: {e}")))?;
        }

        Ok(deleted)
    }

    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats> {
        let tid = fmt_uuid(&tenant_id.0);

        let trace_count: CountRow = self
            .client
            .query(&format!(
                "SELECT count() as cnt FROM traces WHERE tenant_id = {tid}"
            ))
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to count traces: {e}")))?;

        let span_count: CountRow = self
            .client
            .query(&format!(
                "SELECT count() as cnt FROM spans WHERE tenant_id = {tid}"
            ))
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to count spans: {e}")))?;

        let size_row: SizeRow = self
            .client
            .query(&format!(
                "SELECT sum(length(prompt) + length(coalesce(response, ''))) as sz \
                 FROM spans WHERE tenant_id = {tid}"
            ))
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to calculate size: {e}")))?;

        let (oldest_trace, newest_trace) = if trace_count.cnt > 0 {
            let time_row: TimeRangeRow = self
                .client
                .query(&format!(
                    "SELECT min(created_at) as oldest, max(created_at) as newest \
                     FROM traces WHERE tenant_id = {tid}"
                ))
                .fetch_one()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to get time range: {e}")))?;
            (Some(time_row.oldest), Some(time_row.newest))
        } else {
            (None, None)
        };

        Ok(StorageStats {
            total_traces: trace_count.cnt,
            total_spans: span_count.cnt,
            storage_size_bytes: size_row.sz,
            oldest_trace,
            newest_trace,
        })
    }

    async fn get_global_stats(&self) -> Result<StorageStats> {
        let trace_count: CountRow = self
            .client
            .query("SELECT count() as cnt FROM traces")
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to count global traces: {e}")))?;

        let span_count: CountRow = self
            .client
            .query("SELECT count() as cnt FROM spans")
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to count global spans: {e}")))?;

        let size_row: SizeRow = self
            .client
            .query(
                "SELECT sum(length(prompt) + length(coalesce(response, ''))) as sz \
                 FROM spans",
            )
            .fetch_one()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to calculate global size: {e}")))?;

        let (oldest_trace, newest_trace) = if trace_count.cnt > 0 {
            let time_row: TimeRangeRow = self
                .client
                .query(
                    "SELECT min(created_at) as oldest, max(created_at) as newest \
                     FROM traces",
                )
                .fetch_one()
                .await
                .map_err(|e| {
                    LLMTraceError::Storage(format!("Failed to get global time range: {e}"))
                })?;
            (Some(time_row.oldest), Some(time_row.newest))
        } else {
            (None, None)
        };

        Ok(StorageStats {
            total_traces: trace_count.cnt,
            total_spans: span_count.cnt,
            storage_size_bytes: size_row.sz,
            oldest_trace,
            newest_trace,
        })
    }

    async fn health_check(&self) -> Result<()> {
        self.client
            .query("SELECT 1")
            .execute()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Health check failed: {e}")))?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use llmtrace_core::{SecurityFinding, SecuritySeverity, SpanEvent};
    use std::env;

    /// Return a [`ClickHouseTraceRepository`] connected to the test instance,
    /// or skip the test if `LLMTRACE_CLICKHOUSE_URL` is not set.
    async fn test_repo() -> ClickHouseTraceRepository {
        let url = env::var("LLMTRACE_CLICKHOUSE_URL")
            .expect("LLMTRACE_CLICKHOUSE_URL must be set for ClickHouse tests");
        let db = format!("llmtrace_test_{}", Uuid::new_v4().simple());
        ClickHouseTraceRepository::new(&url, &db).await.unwrap()
    }

    /// Build a minimal [`TraceSpan`] for testing.
    fn make_span(
        trace_id: Uuid,
        tenant_id: TenantId,
        provider: LLMProvider,
        model: &str,
    ) -> TraceSpan {
        TraceSpan::new(
            trace_id,
            tenant_id,
            "chat_completion".to_string(),
            provider,
            model.to_string(),
            "Hello, world!".to_string(),
        )
    }

    /// Build a minimal [`TraceEvent`] with one span.
    fn make_trace(tenant_id: TenantId) -> TraceEvent {
        let trace_id = Uuid::new_v4();
        let span = make_span(trace_id, tenant_id, LLMProvider::OpenAI, "gpt-4");
        TraceEvent {
            trace_id,
            tenant_id,
            spans: vec![span],
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_store_trace_query_traces_roundtrip() {
        let repo = test_repo().await;
        let tenant = TenantId::new();
        let trace = make_trace(tenant);

        repo.store_trace(&trace).await.unwrap();

        let results = repo.query_traces(&TraceQuery::new(tenant)).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, trace.trace_id);
        assert_eq!(results[0].tenant_id, tenant);
        assert_eq!(results[0].spans.len(), 1);
        assert_eq!(results[0].spans[0].model_name, "gpt-4");
        assert_eq!(results[0].spans[0].prompt, "Hello, world!");
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_store_span_get_span_roundtrip() {
        let repo = test_repo().await;
        let tenant = TenantId::new();
        let trace_id = Uuid::new_v4();
        let span = make_span(trace_id, tenant, LLMProvider::Anthropic, "claude-3");

        repo.store_span(&span).await.unwrap();

        let retrieved = repo
            .get_span(tenant, span.span_id)
            .await
            .unwrap()
            .expect("span should exist");

        assert_eq!(retrieved.span_id, span.span_id);
        assert_eq!(retrieved.provider, LLMProvider::Anthropic);
        assert_eq!(retrieved.model_name, "claude-3");
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_tenant_isolation() {
        let repo = test_repo().await;
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();

        repo.store_trace(&make_trace(tenant_a)).await.unwrap();
        repo.store_trace(&make_trace(tenant_b)).await.unwrap();

        let results_a = repo.query_traces(&TraceQuery::new(tenant_a)).await.unwrap();
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0].tenant_id, tenant_a);

        let results_b = repo.query_traces(&TraceQuery::new(tenant_b)).await.unwrap();
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0].tenant_id, tenant_b);
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_query_with_time_range() {
        let repo = test_repo().await;
        let tenant = TenantId::new();

        let old_time = Utc::now() - chrono::Duration::hours(2);
        let recent_time = Utc::now();

        let trace_id_old = Uuid::new_v4();
        let mut span_old = make_span(trace_id_old, tenant, LLMProvider::OpenAI, "gpt-4");
        span_old.start_time = old_time;
        let old_trace = TraceEvent {
            trace_id: trace_id_old,
            tenant_id: tenant,
            spans: vec![span_old],
            created_at: old_time,
        };

        let trace_id_new = Uuid::new_v4();
        let mut span_new = make_span(trace_id_new, tenant, LLMProvider::OpenAI, "gpt-4");
        span_new.start_time = recent_time;
        let new_trace = TraceEvent {
            trace_id: trace_id_new,
            tenant_id: tenant,
            spans: vec![span_new],
            created_at: recent_time,
        };

        repo.store_trace(&old_trace).await.unwrap();
        repo.store_trace(&new_trace).await.unwrap();

        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let query = TraceQuery::new(tenant).with_time_range(one_hour_ago, Utc::now());
        let results = repo.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, trace_id_new);
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_query_with_provider_filter() {
        let repo = test_repo().await;
        let tenant = TenantId::new();

        let tid1 = Uuid::new_v4();
        let t1 = TraceEvent {
            trace_id: tid1,
            tenant_id: tenant,
            spans: vec![make_span(tid1, tenant, LLMProvider::OpenAI, "gpt-4")],
            created_at: Utc::now(),
        };
        let tid2 = Uuid::new_v4();
        let t2 = TraceEvent {
            trace_id: tid2,
            tenant_id: tenant,
            spans: vec![make_span(tid2, tenant, LLMProvider::Anthropic, "claude-3")],
            created_at: Utc::now(),
        };

        repo.store_trace(&t1).await.unwrap();
        repo.store_trace(&t2).await.unwrap();

        let query = TraceQuery::new(tenant).with_provider(LLMProvider::Anthropic);
        let results = repo.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, tid2);
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_query_with_security_score_range() {
        let repo = test_repo().await;
        let tenant = TenantId::new();

        let tid = Uuid::new_v4();
        let mut span = make_span(tid, tenant, LLMProvider::OpenAI, "gpt-4");
        span.add_security_finding(SecurityFinding::new(
            SecuritySeverity::Critical,
            "prompt_injection".to_string(),
            "test finding".to_string(),
            0.99,
        ));
        let high_score_trace = TraceEvent {
            trace_id: tid,
            tenant_id: tenant,
            spans: vec![span],
            created_at: Utc::now(),
        };

        repo.store_trace(&high_score_trace).await.unwrap();
        repo.store_trace(&make_trace(tenant)).await.unwrap();

        let query = TraceQuery::new(tenant).with_security_score_range(80, 100);
        let results = repo.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, tid);
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_delete_traces_before() {
        let repo = test_repo().await;
        let tenant = TenantId::new();

        let old_time = Utc::now() - chrono::Duration::hours(2);
        let recent_time = Utc::now();

        let tid_old = Uuid::new_v4();
        let old_trace = TraceEvent {
            trace_id: tid_old,
            tenant_id: tenant,
            spans: vec![make_span(tid_old, tenant, LLMProvider::OpenAI, "gpt-4")],
            created_at: old_time,
        };
        let tid_new = Uuid::new_v4();
        let new_trace = TraceEvent {
            trace_id: tid_new,
            tenant_id: tenant,
            spans: vec![make_span(tid_new, tenant, LLMProvider::OpenAI, "gpt-4")],
            created_at: recent_time,
        };

        repo.store_trace(&old_trace).await.unwrap();
        repo.store_trace(&new_trace).await.unwrap();

        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let deleted = repo.delete_traces_before(tenant, cutoff).await.unwrap();
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_get_stats() {
        let repo = test_repo().await;
        let tenant = TenantId::new();

        repo.store_trace(&make_trace(tenant)).await.unwrap();
        repo.store_trace(&make_trace(tenant)).await.unwrap();

        let stats = repo.get_stats(tenant).await.unwrap();
        assert_eq!(stats.total_traces, 2);
        assert_eq!(stats.total_spans, 2);
        assert!(stats.storage_size_bytes > 0);
        assert!(stats.oldest_trace.is_some());
        assert!(stats.newest_trace.is_some());
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_health_check() {
        let repo = test_repo().await;
        assert!(repo.health_check().await.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires a running ClickHouse instance"]
    async fn test_roundtrip_complex_span_fields() {
        let repo = test_repo().await;
        let tenant = TenantId::new();
        let trace_id = Uuid::new_v4();

        let mut span = make_span(
            trace_id,
            tenant,
            LLMProvider::Custom("my-llm".to_string()),
            "custom-v1",
        );
        span.response = Some("I am an AI assistant.".to_string());
        span.prompt_tokens = Some(10);
        span.completion_tokens = Some(20);
        span.total_tokens = Some(30);
        span.time_to_first_token_ms = Some(42);
        span.duration_ms = Some(123);
        span.status_code = Some(200);
        span.estimated_cost_usd = Some(0.0015);
        span.tags.insert("env".to_string(), "test".to_string());
        span.add_event(
            SpanEvent::new("token_received".to_string(), "first chunk".to_string())
                .with_data("index".to_string(), "0".to_string()),
        );
        span.add_security_finding(SecurityFinding::new(
            SecuritySeverity::Medium,
            "pii_detected".to_string(),
            "email found".to_string(),
            0.85,
        ));

        let trace = TraceEvent {
            trace_id,
            tenant_id: tenant,
            spans: vec![span.clone()],
            created_at: Utc::now(),
        };

        repo.store_trace(&trace).await.unwrap();

        let retrieved = repo
            .get_span(tenant, span.span_id)
            .await
            .unwrap()
            .expect("span should exist");

        assert_eq!(
            retrieved.provider,
            LLMProvider::Custom("my-llm".to_string())
        );
        assert_eq!(retrieved.response.as_deref(), Some("I am an AI assistant."));
        assert_eq!(retrieved.prompt_tokens, Some(10));
        assert_eq!(retrieved.completion_tokens, Some(20));
        assert_eq!(retrieved.total_tokens, Some(30));
        assert_eq!(retrieved.time_to_first_token_ms, Some(42));
        assert_eq!(retrieved.duration_ms, Some(123));
        assert_eq!(retrieved.status_code, Some(200));
        assert!((retrieved.estimated_cost_usd.unwrap() - 0.0015).abs() < f64::EPSILON);
        assert_eq!(retrieved.security_score, Some(60));
        assert_eq!(retrieved.security_findings.len(), 1);
        assert_eq!(retrieved.security_findings[0].finding_type, "pii_detected");
        assert_eq!(retrieved.tags.get("env"), Some(&"test".to_string()));
        assert_eq!(retrieved.events.len(), 1);
        assert_eq!(retrieved.events[0].event_type, "token_received");
    }
}
