//! SQLite storage backend implementations.
//!
//! Provides [`SqliteTraceRepository`] for trace/span storage and
//! [`SqliteMetadataRepository`] for tenant/config/audit storage,
//! both backed by a shared SQLite connection pool.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use llmtrace_core::{
    AgentAction, AuditEvent, AuditQuery, LLMProvider, LLMTraceError, MetadataRepository, Result,
    SecurityFinding, SpanEvent, StorageStats, Tenant, TenantConfig, TenantId, TraceEvent,
    TraceQuery, TraceRepository, TraceSpan,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Schema migrations
// ---------------------------------------------------------------------------

const TRACE_MIGRATIONS: &[&str] = &[
    // Trace-level metadata
    "CREATE TABLE IF NOT EXISTS traces (
        trace_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, trace_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_traces_created ON traces(tenant_id, created_at)",
    // Span-level data with individual columns for efficient filtering
    "CREATE TABLE IF NOT EXISTS spans (
        span_id TEXT NOT NULL,
        trace_id TEXT NOT NULL,
        parent_span_id TEXT,
        tenant_id TEXT NOT NULL,
        operation_name TEXT NOT NULL,
        start_time TEXT NOT NULL,
        end_time TEXT,
        provider TEXT NOT NULL,
        model_name TEXT NOT NULL,
        prompt TEXT NOT NULL,
        response TEXT,
        prompt_tokens INTEGER,
        completion_tokens INTEGER,
        total_tokens INTEGER,
        time_to_first_token_ms INTEGER,
        duration_ms INTEGER,
        status_code INTEGER,
        error_message TEXT,
        estimated_cost_usd REAL,
        security_score INTEGER,
        security_findings TEXT NOT NULL DEFAULT '[]',
        tags TEXT NOT NULL DEFAULT '{}',
        events TEXT NOT NULL DEFAULT '[]',
        PRIMARY KEY (tenant_id, span_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(tenant_id, trace_id)",
    "CREATE INDEX IF NOT EXISTS idx_spans_time ON spans(tenant_id, start_time)",
    "CREATE INDEX IF NOT EXISTS idx_spans_provider ON spans(tenant_id, provider)",
    "CREATE INDEX IF NOT EXISTS idx_spans_model ON spans(tenant_id, model_name)",
    "CREATE INDEX IF NOT EXISTS idx_spans_security ON spans(tenant_id, security_score)",
    "CREATE INDEX IF NOT EXISTS idx_spans_operation ON spans(tenant_id, operation_name)",
    // Loop 18: agent actions column
    "ALTER TABLE spans ADD COLUMN agent_actions TEXT NOT NULL DEFAULT '[]'",
];

const METADATA_MIGRATIONS: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS tenants (
        id TEXT NOT NULL PRIMARY KEY,
        name TEXT NOT NULL,
        plan TEXT NOT NULL,
        created_at TEXT NOT NULL,
        config TEXT NOT NULL DEFAULT '{}'
    )",
    "CREATE TABLE IF NOT EXISTS tenant_configs (
        tenant_id TEXT NOT NULL PRIMARY KEY,
        security_thresholds TEXT NOT NULL DEFAULT '{}',
        feature_flags TEXT NOT NULL DEFAULT '{}'
    )",
    "CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT NOT NULL PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        actor TEXT NOT NULL,
        resource TEXT NOT NULL,
        data TEXT NOT NULL DEFAULT '{}',
        timestamp TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id, timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(tenant_id, event_type)",
];

// ---------------------------------------------------------------------------
// Shared pool builder
// ---------------------------------------------------------------------------

/// Open (or create) a SQLite connection pool configured for LLMTrace.
pub(crate) async fn open_pool(database_url: &str) -> Result<SqlitePool> {
    let connect_opts = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid database URL: {e}")))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);

    // For in-memory databases every connection gets its own database, so
    // restrict the pool to a single connection to keep a consistent view.
    let max_conns: u32 = if database_url.contains(":memory:") {
        1
    } else {
        10
    };

    sqlx::pool::PoolOptions::<Sqlite>::new()
        .max_connections(max_conns)
        .connect_with(connect_opts)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to connect to SQLite: {e}")))
}

/// Run a list of migration statements against the given pool.
///
/// `ALTER TABLE … ADD COLUMN` statements are allowed to fail silently
/// (the column may already exist from a previous run).
pub(crate) async fn run_migrations(pool: &SqlitePool, statements: &[&str]) -> Result<()> {
    for statement in statements {
        let result = sqlx::query(statement).execute(pool).await;
        match result {
            Ok(_) => {}
            Err(e) => {
                let is_alter_add = statement.to_uppercase().contains("ALTER TABLE")
                    && statement.to_uppercase().contains("ADD COLUMN");
                let is_duplicate = e.to_string().contains("duplicate column");
                if is_alter_add && is_duplicate {
                    // Column already exists — safe to ignore
                    continue;
                }
                return Err(LLMTraceError::Storage(format!("Migration failed: {e}")));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Serialisation helpers
// ---------------------------------------------------------------------------

/// Serialize an [`LLMProvider`] for storage as TEXT.
fn serialize_provider(provider: &LLMProvider) -> String {
    serde_json::to_string(provider).expect("LLMProvider serialization cannot fail")
}

/// Deserialize an [`LLMProvider`] from its stored TEXT representation.
fn deserialize_provider(s: &str) -> Result<LLMProvider> {
    serde_json::from_str(s)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid provider value '{s}': {e}")))
}

/// Parse a [`Uuid`] from a TEXT column value.
fn parse_uuid(s: &str) -> Result<Uuid> {
    Uuid::parse_str(s).map_err(|e| LLMTraceError::Storage(format!("Invalid UUID '{s}': {e}")))
}

/// Parse a [`DateTime<Utc>`] from an RFC 3339 TEXT column value.
fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| LLMTraceError::Storage(format!("Invalid datetime '{s}': {e}")))
}

// ---------------------------------------------------------------------------
// Row ↔ TraceSpan conversion
// ---------------------------------------------------------------------------

/// Reconstruct a [`TraceSpan`] from a SQLite row.
fn span_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<TraceSpan> {
    let trace_id = parse_uuid(&row.get::<String, _>("trace_id"))?;
    let span_id = parse_uuid(&row.get::<String, _>("span_id"))?;
    let parent_span_id = row
        .get::<Option<String>, _>("parent_span_id")
        .map(|s| parse_uuid(&s))
        .transpose()?;
    let tenant_id = TenantId(parse_uuid(&row.get::<String, _>("tenant_id"))?);
    let operation_name: String = row.get("operation_name");
    let start_time = parse_datetime(&row.get::<String, _>("start_time"))?;
    let end_time = row
        .get::<Option<String>, _>("end_time")
        .map(|s| parse_datetime(&s))
        .transpose()?;
    let provider = deserialize_provider(&row.get::<String, _>("provider"))?;
    let model_name: String = row.get("model_name");
    let prompt: String = row.get("prompt");
    let response: Option<String> = row.get("response");
    let prompt_tokens = row.get::<Option<i64>, _>("prompt_tokens").map(|v| v as u32);
    let completion_tokens = row
        .get::<Option<i64>, _>("completion_tokens")
        .map(|v| v as u32);
    let total_tokens = row.get::<Option<i64>, _>("total_tokens").map(|v| v as u32);
    let time_to_first_token_ms = row
        .get::<Option<i64>, _>("time_to_first_token_ms")
        .map(|v| v as u64);
    let duration_ms = row.get::<Option<i64>, _>("duration_ms").map(|v| v as u64);
    let status_code = row.get::<Option<i64>, _>("status_code").map(|v| v as u16);
    let error_message: Option<String> = row.get("error_message");
    let estimated_cost_usd: Option<f64> = row.get("estimated_cost_usd");
    let security_score = row.get::<Option<i64>, _>("security_score").map(|v| v as u8);

    let security_findings: Vec<SecurityFinding> = {
        let raw: String = row.get("security_findings");
        serde_json::from_str(&raw)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid security_findings JSON: {e}")))?
    };
    let tags: HashMap<String, String> = {
        let raw: String = row.get("tags");
        serde_json::from_str(&raw)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid tags JSON: {e}")))?
    };
    let events: Vec<SpanEvent> = {
        let raw: String = row.get("events");
        serde_json::from_str(&raw)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid events JSON: {e}")))?
    };
    let agent_actions: Vec<AgentAction> = {
        let raw: String = row.get("agent_actions");
        serde_json::from_str(&raw)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid agent_actions JSON: {e}")))?
    };

    Ok(TraceSpan {
        trace_id,
        span_id,
        parent_span_id,
        tenant_id,
        operation_name,
        start_time,
        end_time,
        provider,
        model_name,
        prompt,
        response,
        prompt_tokens,
        completion_tokens,
        total_tokens,
        time_to_first_token_ms,
        duration_ms,
        status_code,
        error_message,
        estimated_cost_usd,
        security_score,
        security_findings,
        tags,
        events,
        agent_actions,
    })
}

// ===========================================================================
// SqliteTraceRepository
// ===========================================================================

/// SQLite-backed trace repository.
///
/// Stores trace metadata in a `traces` table and individual spans in a `spans`
/// table with proper indexes for efficient querying by tenant, time range,
/// provider, model, and security score.
pub struct SqliteTraceRepository {
    pool: SqlitePool,
}

impl SqliteTraceRepository {
    /// Open (or create) a SQLite database and run trace schema migrations.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example() -> llmtrace_core::Result<()> {
    /// let repo = llmtrace_storage::SqliteTraceRepository::new("sqlite::memory:").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = open_pool(database_url).await?;
        run_migrations(&pool, TRACE_MIGRATIONS).await?;
        Ok(Self { pool })
    }

    /// Create from an existing pool (used by [`StorageProfile`](crate::StorageProfile) factory).
    pub(crate) async fn from_pool(pool: SqlitePool) -> Result<Self> {
        run_migrations(&pool, TRACE_MIGRATIONS).await?;
        Ok(Self { pool })
    }

    /// Insert a single span using the provided executor (pool or transaction).
    async fn insert_span<'e, E>(&self, executor: E, span: &TraceSpan) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        let security_findings_json = serde_json::to_string(&span.security_findings)
            .map_err(|e| LLMTraceError::Storage(format!("serialize security_findings: {e}")))?;
        let tags_json = serde_json::to_string(&span.tags)
            .map_err(|e| LLMTraceError::Storage(format!("serialize tags: {e}")))?;
        let events_json = serde_json::to_string(&span.events)
            .map_err(|e| LLMTraceError::Storage(format!("serialize events: {e}")))?;
        let agent_actions_json = serde_json::to_string(&span.agent_actions)
            .map_err(|e| LLMTraceError::Storage(format!("serialize agent_actions: {e}")))?;

        sqlx::query(
            "INSERT OR REPLACE INTO spans (
                span_id, trace_id, parent_span_id, tenant_id, operation_name,
                start_time, end_time, provider, model_name, prompt,
                response, prompt_tokens, completion_tokens, total_tokens,
                time_to_first_token_ms, duration_ms, status_code, error_message,
                estimated_cost_usd, security_score, security_findings, tags, events,
                agent_actions
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5,
                ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18,
                ?19, ?20, ?21, ?22, ?23,
                ?24
            )",
        )
        .bind(span.span_id.to_string())
        .bind(span.trace_id.to_string())
        .bind(span.parent_span_id.map(|id| id.to_string()))
        .bind(span.tenant_id.0.to_string())
        .bind(&span.operation_name)
        .bind(span.start_time.to_rfc3339())
        .bind(span.end_time.map(|t| t.to_rfc3339()))
        .bind(serialize_provider(&span.provider))
        .bind(&span.model_name)
        .bind(&span.prompt)
        .bind(span.response.as_deref())
        .bind(span.prompt_tokens.map(|v| v as i64))
        .bind(span.completion_tokens.map(|v| v as i64))
        .bind(span.total_tokens.map(|v| v as i64))
        .bind(span.time_to_first_token_ms.map(|v| v as i64))
        .bind(span.duration_ms.map(|v| v as i64))
        .bind(span.status_code.map(|v| v as i64))
        .bind(span.error_message.as_deref())
        .bind(span.estimated_cost_usd)
        .bind(span.security_score.map(|v| v as i64))
        .bind(&security_findings_json)
        .bind(&tags_json)
        .bind(&events_json)
        .bind(&agent_actions_json)
        .execute(executor)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to insert span: {e}")))?;

        Ok(())
    }

    /// Load all spans belonging to a set of trace IDs for a given tenant.
    async fn load_spans_for_traces(
        &self,
        tenant_id: &TenantId,
        trace_ids: &[String],
    ) -> Result<HashMap<String, Vec<TraceSpan>>> {
        if trace_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM spans WHERE tenant_id = ");
        qb.push_bind(tenant_id.0.to_string());
        qb.push(" AND trace_id IN (");
        let mut sep = qb.separated(", ");
        for tid in trace_ids {
            sep.push_bind(tid.clone());
        }
        sep.push_unseparated(") ORDER BY start_time ASC");

        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to load spans: {e}")))?;

        let mut grouped: HashMap<String, Vec<TraceSpan>> = HashMap::new();
        for row in &rows {
            let span = span_from_row(row)?;
            grouped
                .entry(span.trace_id.to_string())
                .or_default()
                .push(span);
        }
        Ok(grouped)
    }

    /// Build a dynamic span-filter query, returning matching `trace_id` values.
    fn build_trace_id_query<'args>(&self, query: &TraceQuery) -> QueryBuilder<'args, Sqlite> {
        let mut qb = QueryBuilder::<Sqlite>::new(
            "SELECT DISTINCT s.trace_id FROM spans s \
             JOIN traces t ON s.trace_id = t.trace_id AND s.tenant_id = t.tenant_id \
             WHERE s.tenant_id = ",
        );
        qb.push_bind(query.tenant_id.0.to_string());

        if let Some(ref trace_id) = query.trace_id {
            qb.push(" AND s.trace_id = ");
            qb.push_bind(trace_id.to_string());
        }
        if let Some(ref start) = query.start_time {
            qb.push(" AND s.start_time >= ");
            qb.push_bind(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            qb.push(" AND s.start_time <= ");
            qb.push_bind(end.to_rfc3339());
        }
        if let Some(ref provider) = query.provider {
            qb.push(" AND s.provider = ");
            qb.push_bind(serialize_provider(provider));
        }
        if let Some(ref model) = query.model_name {
            qb.push(" AND s.model_name = ");
            qb.push_bind(model.clone());
        }
        if let Some(ref op) = query.operation_name {
            qb.push(" AND s.operation_name = ");
            qb.push_bind(op.clone());
        }
        if let Some(min) = query.min_security_score {
            qb.push(" AND s.security_score >= ");
            qb.push_bind(min as i64);
        }
        if let Some(max) = query.max_security_score {
            qb.push(" AND s.security_score <= ");
            qb.push_bind(max as i64);
        }

        qb.push(" ORDER BY t.created_at DESC");

        if let Some(limit) = query.limit {
            qb.push(" LIMIT ");
            qb.push_bind(limit as i64);
        }
        if let Some(offset) = query.offset {
            qb.push(" OFFSET ");
            qb.push_bind(offset as i64);
        }

        qb
    }

    /// Build a dynamic span-filter query returning full span rows.
    fn build_span_query<'args>(&self, query: &TraceQuery) -> QueryBuilder<'args, Sqlite> {
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM spans WHERE tenant_id = ");
        qb.push_bind(query.tenant_id.0.to_string());

        if let Some(ref trace_id) = query.trace_id {
            qb.push(" AND trace_id = ");
            qb.push_bind(trace_id.to_string());
        }
        if let Some(ref start) = query.start_time {
            qb.push(" AND start_time >= ");
            qb.push_bind(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            qb.push(" AND start_time <= ");
            qb.push_bind(end.to_rfc3339());
        }
        if let Some(ref provider) = query.provider {
            qb.push(" AND provider = ");
            qb.push_bind(serialize_provider(provider));
        }
        if let Some(ref model) = query.model_name {
            qb.push(" AND model_name = ");
            qb.push_bind(model.clone());
        }
        if let Some(ref op) = query.operation_name {
            qb.push(" AND operation_name = ");
            qb.push_bind(op.clone());
        }
        if let Some(min) = query.min_security_score {
            qb.push(" AND security_score >= ");
            qb.push_bind(min as i64);
        }
        if let Some(max) = query.max_security_score {
            qb.push(" AND security_score <= ");
            qb.push_bind(max as i64);
        }

        qb.push(" ORDER BY start_time DESC");

        if let Some(limit) = query.limit {
            qb.push(" LIMIT ");
            qb.push_bind(limit as i64);
        }
        if let Some(offset) = query.offset {
            qb.push(" OFFSET ");
            qb.push_bind(offset as i64);
        }

        qb
    }
}

#[async_trait]
impl TraceRepository for SqliteTraceRepository {
    async fn store_trace(&self, trace: &TraceEvent) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to begin transaction: {e}")))?;

        sqlx::query(
            "INSERT OR REPLACE INTO traces (trace_id, tenant_id, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(trace.trace_id.to_string())
        .bind(trace.tenant_id.0.to_string())
        .bind(trace.created_at.to_rfc3339())
        .execute(&mut *tx)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to insert trace: {e}")))?;

        for span in &trace.spans {
            self.insert_span(&mut *tx, span).await?;
        }

        tx.commit()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to commit transaction: {e}")))?;

        Ok(())
    }

    async fn store_span(&self, span: &TraceSpan) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to begin transaction: {e}")))?;

        sqlx::query(
            "INSERT OR IGNORE INTO traces (trace_id, tenant_id, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(span.trace_id.to_string())
        .bind(span.tenant_id.0.to_string())
        .bind(span.start_time.to_rfc3339())
        .execute(&mut *tx)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to ensure trace row: {e}")))?;

        self.insert_span(&mut *tx, span).await?;

        tx.commit()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to commit transaction: {e}")))?;

        Ok(())
    }

    async fn query_traces(&self, query: &TraceQuery) -> Result<Vec<TraceEvent>> {
        let mut qb = self.build_trace_id_query(query);
        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query trace IDs: {e}")))?;

        let trace_ids: Vec<String> = rows.iter().map(|r| r.get("trace_id")).collect();
        if trace_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut meta_qb = QueryBuilder::<Sqlite>::new("SELECT * FROM traces WHERE tenant_id = ");
        meta_qb.push_bind(query.tenant_id.0.to_string());
        meta_qb.push(" AND trace_id IN (");
        let mut sep = meta_qb.separated(", ");
        for tid in &trace_ids {
            sep.push_bind(tid.clone());
        }
        sep.push_unseparated(") ORDER BY created_at DESC");

        let meta_rows =
            meta_qb.build().fetch_all(&self.pool).await.map_err(|e| {
                LLMTraceError::Storage(format!("Failed to load trace metadata: {e}"))
            })?;

        let spans_map = self
            .load_spans_for_traces(&query.tenant_id, &trace_ids)
            .await?;

        let mut results = Vec::with_capacity(meta_rows.len());
        for row in &meta_rows {
            let tid_str: String = row.get("trace_id");
            let trace_id = parse_uuid(&tid_str)?;
            let tenant_id = TenantId(parse_uuid(&row.get::<String, _>("tenant_id"))?);
            let created_at = parse_datetime(&row.get::<String, _>("created_at"))?;
            let spans = spans_map.get(&tid_str).cloned().unwrap_or_default();

            results.push(TraceEvent {
                trace_id,
                tenant_id,
                spans,
                created_at,
            });
        }

        Ok(results)
    }

    async fn query_spans(&self, query: &TraceQuery) -> Result<Vec<TraceSpan>> {
        let mut qb = self.build_span_query(query);
        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query spans: {e}")))?;

        rows.iter().map(span_from_row).collect()
    }

    async fn get_trace(&self, tenant_id: TenantId, trace_id: Uuid) -> Result<Option<TraceEvent>> {
        let row = sqlx::query("SELECT * FROM traces WHERE tenant_id = ?1 AND trace_id = ?2")
            .bind(tenant_id.0.to_string())
            .bind(trace_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get trace: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let created_at = parse_datetime(&row.get::<String, _>("created_at"))?;

        let span_rows = sqlx::query(
            "SELECT * FROM spans WHERE tenant_id = ?1 AND trace_id = ?2 ORDER BY start_time ASC",
        )
        .bind(tenant_id.0.to_string())
        .bind(trace_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to load trace spans: {e}")))?;

        let spans: Vec<TraceSpan> = span_rows.iter().map(span_from_row).collect::<Result<_>>()?;

        Ok(Some(TraceEvent {
            trace_id,
            tenant_id,
            spans,
            created_at,
        }))
    }

    async fn get_span(&self, tenant_id: TenantId, span_id: Uuid) -> Result<Option<TraceSpan>> {
        let row = sqlx::query("SELECT * FROM spans WHERE tenant_id = ?1 AND span_id = ?2")
            .bind(tenant_id.0.to_string())
            .bind(span_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get span: {e}")))?;

        match row {
            Some(ref r) => Ok(Some(span_from_row(r)?)),
            None => Ok(None),
        }
    }

    async fn delete_traces_before(
        &self,
        tenant_id: TenantId,
        before: DateTime<Utc>,
    ) -> Result<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to begin transaction: {e}")))?;

        let before_str = before.to_rfc3339();
        let tid = tenant_id.0.to_string();

        sqlx::query(
            "DELETE FROM spans WHERE tenant_id = ?1 AND trace_id IN \
             (SELECT trace_id FROM traces WHERE tenant_id = ?2 AND created_at < ?3)",
        )
        .bind(&tid)
        .bind(&tid)
        .bind(&before_str)
        .execute(&mut *tx)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to delete spans: {e}")))?;

        let result = sqlx::query("DELETE FROM traces WHERE tenant_id = ?1 AND created_at < ?2")
            .bind(&tid)
            .bind(&before_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to delete traces: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to commit delete: {e}")))?;

        Ok(result.rows_affected())
    }

    async fn get_stats(&self, tenant_id: TenantId) -> Result<StorageStats> {
        let tid = tenant_id.0.to_string();

        let trace_count: i64 =
            sqlx::query("SELECT COUNT(*) as cnt FROM traces WHERE tenant_id = ?1")
                .bind(&tid)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to count traces: {e}")))?
                .get("cnt");

        let span_count: i64 = sqlx::query("SELECT COUNT(*) as cnt FROM spans WHERE tenant_id = ?1")
            .bind(&tid)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to count spans: {e}")))?
            .get("cnt");

        let size_row = sqlx::query(
            "SELECT COALESCE(SUM(LENGTH(prompt) + COALESCE(LENGTH(response), 0)), 0) as sz \
             FROM spans WHERE tenant_id = ?1",
        )
        .bind(&tid)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to calculate size: {e}")))?;
        let storage_size_bytes: i64 = size_row.get("sz");

        let time_row = sqlx::query(
            "SELECT MIN(created_at) as oldest, MAX(created_at) as newest \
             FROM traces WHERE tenant_id = ?1",
        )
        .bind(&tid)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to get time range: {e}")))?;

        let oldest_trace = time_row
            .get::<Option<String>, _>("oldest")
            .map(|s| parse_datetime(&s))
            .transpose()?;
        let newest_trace = time_row
            .get::<Option<String>, _>("newest")
            .map(|s| parse_datetime(&s))
            .transpose()?;

        Ok(StorageStats {
            total_traces: trace_count as u64,
            total_spans: span_count as u64,
            storage_size_bytes: storage_size_bytes as u64,
            oldest_trace,
            newest_trace,
        })
    }

    async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Health check failed: {e}")))?;
        Ok(())
    }
}

// ===========================================================================
// SqliteMetadataRepository
// ===========================================================================

/// SQLite-backed metadata repository for tenants, configurations, and audit events.
pub struct SqliteMetadataRepository {
    pool: SqlitePool,
}

impl SqliteMetadataRepository {
    /// Open (or create) a SQLite database and run metadata schema migrations.
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = open_pool(database_url).await?;
        run_migrations(&pool, METADATA_MIGRATIONS).await?;
        Ok(Self { pool })
    }

    /// Create from an existing pool (used by [`StorageProfile`](crate::StorageProfile) factory).
    pub(crate) async fn from_pool(pool: SqlitePool) -> Result<Self> {
        run_migrations(&pool, METADATA_MIGRATIONS).await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl MetadataRepository for SqliteMetadataRepository {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        let config_json = serde_json::to_string(&tenant.config)
            .map_err(|e| LLMTraceError::Storage(format!("serialize tenant config: {e}")))?;

        sqlx::query(
            "INSERT INTO tenants (id, name, plan, created_at, config) VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(tenant.id.0.to_string())
        .bind(&tenant.name)
        .bind(&tenant.plan)
        .bind(tenant.created_at.to_rfc3339())
        .bind(&config_json)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to create tenant: {e}")))?;

        Ok(())
    }

    async fn get_tenant(&self, id: TenantId) -> Result<Option<Tenant>> {
        let row = sqlx::query("SELECT * FROM tenants WHERE id = ?1")
            .bind(id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get tenant: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let config_str: String = row.get("config");
        let config: serde_json::Value = serde_json::from_str(&config_str)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid tenant config JSON: {e}")))?;

        Ok(Some(Tenant {
            id: TenantId(parse_uuid(&row.get::<String, _>("id"))?),
            name: row.get("name"),
            plan: row.get("plan"),
            created_at: parse_datetime(&row.get::<String, _>("created_at"))?,
            config,
        }))
    }

    async fn update_tenant(&self, tenant: &Tenant) -> Result<()> {
        let config_json = serde_json::to_string(&tenant.config)
            .map_err(|e| LLMTraceError::Storage(format!("serialize tenant config: {e}")))?;

        let result =
            sqlx::query("UPDATE tenants SET name = ?1, plan = ?2, config = ?3 WHERE id = ?4")
                .bind(&tenant.name)
                .bind(&tenant.plan)
                .bind(&config_json)
                .bind(tenant.id.0.to_string())
                .execute(&self.pool)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to update tenant: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(LLMTraceError::InvalidTenant {
                tenant_id: tenant.id,
            });
        }
        Ok(())
    }

    async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let rows = sqlx::query("SELECT * FROM tenants ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to list tenants: {e}")))?;

        rows.iter()
            .map(|row| {
                let config_str: String = row.get("config");
                let config: serde_json::Value = serde_json::from_str(&config_str).map_err(|e| {
                    LLMTraceError::Storage(format!("Invalid tenant config JSON: {e}"))
                })?;
                Ok(Tenant {
                    id: TenantId(parse_uuid(&row.get::<String, _>("id"))?),
                    name: row.get("name"),
                    plan: row.get("plan"),
                    created_at: parse_datetime(&row.get::<String, _>("created_at"))?,
                    config,
                })
            })
            .collect()
    }

    async fn delete_tenant(&self, id: TenantId) -> Result<()> {
        sqlx::query("DELETE FROM tenants WHERE id = ?1")
            .bind(id.0.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to delete tenant: {e}")))?;
        Ok(())
    }

    async fn get_tenant_config(&self, tenant_id: TenantId) -> Result<Option<TenantConfig>> {
        let row = sqlx::query("SELECT * FROM tenant_configs WHERE tenant_id = ?1")
            .bind(tenant_id.0.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get tenant config: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let thresholds_str: String = row.get("security_thresholds");
        let flags_str: String = row.get("feature_flags");

        Ok(Some(TenantConfig {
            tenant_id: TenantId(parse_uuid(&row.get::<String, _>("tenant_id"))?),
            security_thresholds: serde_json::from_str(&thresholds_str).map_err(|e| {
                LLMTraceError::Storage(format!("Invalid security_thresholds JSON: {e}"))
            })?,
            feature_flags: serde_json::from_str(&flags_str)
                .map_err(|e| LLMTraceError::Storage(format!("Invalid feature_flags JSON: {e}")))?,
        }))
    }

    async fn upsert_tenant_config(&self, config: &TenantConfig) -> Result<()> {
        let thresholds_json = serde_json::to_string(&config.security_thresholds)
            .map_err(|e| LLMTraceError::Storage(format!("serialize thresholds: {e}")))?;
        let flags_json = serde_json::to_string(&config.feature_flags)
            .map_err(|e| LLMTraceError::Storage(format!("serialize feature_flags: {e}")))?;

        sqlx::query(
            "INSERT INTO tenant_configs (tenant_id, security_thresholds, feature_flags)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(tenant_id) DO UPDATE SET
                security_thresholds = excluded.security_thresholds,
                feature_flags = excluded.feature_flags",
        )
        .bind(config.tenant_id.0.to_string())
        .bind(&thresholds_json)
        .bind(&flags_json)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to upsert tenant config: {e}")))?;

        Ok(())
    }

    async fn record_audit_event(&self, event: &AuditEvent) -> Result<()> {
        let data_json = serde_json::to_string(&event.data)
            .map_err(|e| LLMTraceError::Storage(format!("serialize audit data: {e}")))?;

        sqlx::query(
            "INSERT INTO audit_events (id, tenant_id, event_type, actor, resource, data, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(event.id.to_string())
        .bind(event.tenant_id.0.to_string())
        .bind(&event.event_type)
        .bind(&event.actor)
        .bind(&event.resource)
        .bind(&data_json)
        .bind(event.timestamp.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to record audit event: {e}")))?;

        Ok(())
    }

    async fn query_audit_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM audit_events WHERE tenant_id = ");
        qb.push_bind(query.tenant_id.0.to_string());

        if let Some(ref event_type) = query.event_type {
            qb.push(" AND event_type = ");
            qb.push_bind(event_type.clone());
        }
        if let Some(ref start) = query.start_time {
            qb.push(" AND timestamp >= ");
            qb.push_bind(start.to_rfc3339());
        }
        if let Some(ref end) = query.end_time {
            qb.push(" AND timestamp <= ");
            qb.push_bind(end.to_rfc3339());
        }

        qb.push(" ORDER BY timestamp DESC");

        if let Some(limit) = query.limit {
            qb.push(" LIMIT ");
            qb.push_bind(limit as i64);
        }
        if let Some(offset) = query.offset {
            qb.push(" OFFSET ");
            qb.push_bind(offset as i64);
        }

        let rows =
            qb.build().fetch_all(&self.pool).await.map_err(|e| {
                LLMTraceError::Storage(format!("Failed to query audit events: {e}"))
            })?;

        rows.iter()
            .map(|row| {
                let data_str: String = row.get("data");
                let data: serde_json::Value = serde_json::from_str(&data_str).map_err(|e| {
                    LLMTraceError::Storage(format!("Invalid audit event data JSON: {e}"))
                })?;
                Ok(AuditEvent {
                    id: parse_uuid(&row.get::<String, _>("id"))?,
                    tenant_id: TenantId(parse_uuid(&row.get::<String, _>("tenant_id"))?),
                    event_type: row.get("event_type"),
                    actor: row.get("actor"),
                    resource: row.get("resource"),
                    data,
                    timestamp: parse_datetime(&row.get::<String, _>("timestamp"))?,
                })
            })
            .collect()
    }

    async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Metadata health check failed: {e}")))?;
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

    /// Create a fresh in-memory [`SqliteTraceRepository`] for testing.
    async fn test_storage() -> SqliteTraceRepository {
        SqliteTraceRepository::new("sqlite::memory:").await.unwrap()
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

    // -- basic CRUD --------------------------------------------------------

    #[tokio::test]
    async fn test_store_and_retrieve_trace() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let trace = make_trace(tenant);

        storage.store_trace(&trace).await.unwrap();

        let retrieved = storage
            .get_trace(tenant, trace.trace_id)
            .await
            .unwrap()
            .expect("trace should exist");

        assert_eq!(retrieved.trace_id, trace.trace_id);
        assert_eq!(retrieved.tenant_id, tenant);
        assert_eq!(retrieved.spans.len(), 1);
        assert_eq!(retrieved.spans[0].model_name, "gpt-4");
        assert_eq!(retrieved.spans[0].prompt, "Hello, world!");
    }

    #[tokio::test]
    async fn test_store_span_individually() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let trace_id = Uuid::new_v4();
        let span = make_span(trace_id, tenant, LLMProvider::Anthropic, "claude-3");

        storage.store_span(&span).await.unwrap();

        let retrieved = storage
            .get_span(tenant, span.span_id)
            .await
            .unwrap()
            .expect("span should exist");

        assert_eq!(retrieved.span_id, span.span_id);
        assert_eq!(retrieved.provider, LLMProvider::Anthropic);
        assert_eq!(retrieved.model_name, "claude-3");

        let trace = storage
            .get_trace(tenant, trace_id)
            .await
            .unwrap()
            .expect("parent trace row should exist");
        assert_eq!(trace.spans.len(), 1);
    }

    #[tokio::test]
    async fn test_get_nonexistent_trace() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let result = storage.get_trace(tenant, Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_nonexistent_span() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let result = storage.get_span(tenant, Uuid::new_v4()).await.unwrap();
        assert!(result.is_none());
    }

    // -- query filters -----------------------------------------------------

    #[tokio::test]
    async fn test_query_by_tenant_isolation() {
        let storage = test_storage().await;
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();

        storage.store_trace(&make_trace(tenant_a)).await.unwrap();
        storage.store_trace(&make_trace(tenant_b)).await.unwrap();

        let results_a = storage
            .query_traces(&TraceQuery::new(tenant_a))
            .await
            .unwrap();
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0].tenant_id, tenant_a);

        let results_b = storage
            .query_traces(&TraceQuery::new(tenant_b))
            .await
            .unwrap();
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0].tenant_id, tenant_b);
    }

    #[tokio::test]
    async fn test_query_by_time_range() {
        let storage = test_storage().await;
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

        storage.store_trace(&old_trace).await.unwrap();
        storage.store_trace(&new_trace).await.unwrap();

        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let query = TraceQuery::new(tenant).with_time_range(one_hour_ago, Utc::now());
        let results = storage.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, trace_id_new);
    }

    #[tokio::test]
    async fn test_query_by_provider() {
        let storage = test_storage().await;
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

        storage.store_trace(&t1).await.unwrap();
        storage.store_trace(&t2).await.unwrap();

        let query = TraceQuery::new(tenant).with_provider(LLMProvider::Anthropic);
        let results = storage.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, tid2);
    }

    #[tokio::test]
    async fn test_query_by_security_score() {
        let storage = test_storage().await;
        let tenant = TenantId::new();

        let tid = Uuid::new_v4();
        let mut span = make_span(tid, tenant, LLMProvider::OpenAI, "gpt-4");
        span.add_security_finding(SecurityFinding::new(
            SecuritySeverity::Critical,
            "prompt_injection".to_string(),
            "test finding".to_string(),
            0.99,
        ));

        let trace = TraceEvent {
            trace_id: tid,
            tenant_id: tenant,
            spans: vec![span],
            created_at: Utc::now(),
        };
        storage.store_trace(&trace).await.unwrap();
        storage.store_trace(&make_trace(tenant)).await.unwrap();

        let query = TraceQuery::new(tenant).with_security_score_range(80, 100);
        let results = storage.query_traces(&query).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].trace_id, tid);
    }

    #[tokio::test]
    async fn test_query_with_limit_and_offset() {
        let storage = test_storage().await;
        let tenant = TenantId::new();

        for _ in 0..5 {
            storage.store_trace(&make_trace(tenant)).await.unwrap();
        }

        let query = TraceQuery::new(tenant).with_limit(2);
        let page1 = storage.query_traces(&query).await.unwrap();
        assert_eq!(page1.len(), 2);

        let mut query2 = TraceQuery::new(tenant).with_limit(2);
        query2.offset = Some(2);
        let page2 = storage.query_traces(&query2).await.unwrap();
        assert_eq!(page2.len(), 2);

        let ids1: Vec<Uuid> = page1.iter().map(|t| t.trace_id).collect();
        let ids2: Vec<Uuid> = page2.iter().map(|t| t.trace_id).collect();
        for id in &ids2 {
            assert!(!ids1.contains(id));
        }
    }

    #[tokio::test]
    async fn test_query_nonexistent_tenant() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        storage.store_trace(&make_trace(tenant)).await.unwrap();

        let other_tenant = TenantId::new();
        let results = storage
            .query_traces(&TraceQuery::new(other_tenant))
            .await
            .unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_query_spans_directly() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let trace = make_trace(tenant);
        storage.store_trace(&trace).await.unwrap();

        let spans = storage.query_spans(&TraceQuery::new(tenant)).await.unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].trace_id, trace.trace_id);
    }

    #[tokio::test]
    async fn test_query_spans_by_provider() {
        let storage = test_storage().await;
        let tenant = TenantId::new();

        let tid1 = Uuid::new_v4();
        let tid2 = Uuid::new_v4();
        let s1 = make_span(tid1, tenant, LLMProvider::OpenAI, "gpt-4");
        let s2 = make_span(tid2, tenant, LLMProvider::Anthropic, "claude-3");
        storage.store_span(&s1).await.unwrap();
        storage.store_span(&s2).await.unwrap();

        let query = TraceQuery::new(tenant).with_provider(LLMProvider::OpenAI);
        let spans = storage.query_spans(&query).await.unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].provider, LLMProvider::OpenAI);
    }

    #[tokio::test]
    async fn test_delete_traces_before() {
        let storage = test_storage().await;
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

        storage.store_trace(&old_trace).await.unwrap();
        storage.store_trace(&new_trace).await.unwrap();

        let cutoff = Utc::now() - chrono::Duration::hours(1);
        let deleted = storage.delete_traces_before(tenant, cutoff).await.unwrap();
        assert_eq!(deleted, 1);

        let remaining = storage
            .query_traces(&TraceQuery::new(tenant))
            .await
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].trace_id, tid_new);

        let old_span = storage.get_trace(tenant, tid_old).await.unwrap();
        assert!(old_span.is_none());
    }

    #[tokio::test]
    async fn test_get_stats() {
        let storage = test_storage().await;
        let tenant = TenantId::new();

        storage.store_trace(&make_trace(tenant)).await.unwrap();
        storage.store_trace(&make_trace(tenant)).await.unwrap();

        let stats = storage.get_stats(tenant).await.unwrap();
        assert_eq!(stats.total_traces, 2);
        assert_eq!(stats.total_spans, 2);
        assert!(stats.storage_size_bytes > 0);
        assert!(stats.oldest_trace.is_some());
        assert!(stats.newest_trace.is_some());
    }

    #[tokio::test]
    async fn test_get_stats_empty_tenant() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let stats = storage.get_stats(tenant).await.unwrap();
        assert_eq!(stats.total_traces, 0);
        assert_eq!(stats.total_spans, 0);
        assert_eq!(stats.storage_size_bytes, 0);
        assert!(stats.oldest_trace.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let storage = test_storage().await;
        assert!(storage.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_duplicate_store_is_idempotent() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let trace = make_trace(tenant);

        storage.store_trace(&trace).await.unwrap();
        storage.store_trace(&trace).await.unwrap();

        let results = storage
            .query_traces(&TraceQuery::new(tenant))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[tokio::test]
    async fn test_store_trace_with_no_spans() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let trace = TraceEvent {
            trace_id: Uuid::new_v4(),
            tenant_id: tenant,
            spans: vec![],
            created_at: Utc::now(),
        };

        storage.store_trace(&trace).await.unwrap();

        let retrieved = storage
            .get_trace(tenant, trace.trace_id)
            .await
            .unwrap()
            .expect("trace row should exist");
        assert!(retrieved.spans.is_empty());
    }

    #[tokio::test]
    async fn test_roundtrip_complex_span_fields() {
        let storage = test_storage().await;
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

        storage.store_trace(&trace).await.unwrap();

        let retrieved = storage
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

    #[tokio::test]
    async fn test_trace_with_multiple_spans() {
        let storage = test_storage().await;
        let tenant = TenantId::new();
        let trace_id = Uuid::new_v4();

        let span1 = make_span(trace_id, tenant, LLMProvider::OpenAI, "gpt-4");
        let mut span2 = make_span(trace_id, tenant, LLMProvider::OpenAI, "gpt-4");
        span2.parent_span_id = Some(span1.span_id);
        span2.operation_name = "embedding".to_string();

        let trace = TraceEvent {
            trace_id,
            tenant_id: tenant,
            spans: vec![span1.clone(), span2.clone()],
            created_at: Utc::now(),
        };

        storage.store_trace(&trace).await.unwrap();

        let retrieved = storage
            .get_trace(tenant, trace_id)
            .await
            .unwrap()
            .expect("trace should exist");
        assert_eq!(retrieved.spans.len(), 2);

        let child = retrieved
            .spans
            .iter()
            .find(|s| s.parent_span_id.is_some())
            .expect("child span should be present");
        assert_eq!(child.parent_span_id, Some(span1.span_id));
    }

    // -- Metadata repository tests -----------------------------------------

    async fn test_metadata() -> SqliteMetadataRepository {
        SqliteMetadataRepository::new("sqlite::memory:")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_tenant_crud() {
        let repo = test_metadata().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Acme Corp".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({"max_traces": 10000}),
        };

        repo.create_tenant(&tenant).await.unwrap();

        let retrieved = repo
            .get_tenant(tenant.id)
            .await
            .unwrap()
            .expect("tenant should exist");
        assert_eq!(retrieved.name, "Acme Corp");
        assert_eq!(retrieved.plan, "pro");

        let mut updated = tenant.clone();
        updated.name = "Acme Inc".to_string();
        updated.plan = "enterprise".to_string();
        repo.update_tenant(&updated).await.unwrap();

        let after_update = repo
            .get_tenant(tenant.id)
            .await
            .unwrap()
            .expect("tenant should exist");
        assert_eq!(after_update.name, "Acme Inc");
        assert_eq!(after_update.plan, "enterprise");

        let tenants = repo.list_tenants().await.unwrap();
        assert_eq!(tenants.len(), 1);

        repo.delete_tenant(tenant.id).await.unwrap();
        let gone = repo.get_tenant(tenant.id).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn test_update_nonexistent_tenant_returns_error() {
        let repo = test_metadata().await;
        let tenant = Tenant {
            id: TenantId::new(),
            name: "Ghost".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        let result = repo.update_tenant(&tenant).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_tenant_config_crud() {
        let repo = test_metadata().await;
        let tenant_id = TenantId::new();

        // Create tenant first
        let tenant = Tenant {
            id: tenant_id,
            name: "Test".to_string(),
            plan: "free".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({}),
        };
        repo.create_tenant(&tenant).await.unwrap();

        // No config yet
        let cfg = repo.get_tenant_config(tenant_id).await.unwrap();
        assert!(cfg.is_none());

        // Upsert config
        let mut thresholds = HashMap::new();
        thresholds.insert("alert_min_score".to_string(), 80.0);
        let mut flags = HashMap::new();
        flags.insert("enable_pii".to_string(), true);

        let config = TenantConfig {
            tenant_id,
            security_thresholds: thresholds,
            feature_flags: flags,
        };
        repo.upsert_tenant_config(&config).await.unwrap();

        let retrieved = repo
            .get_tenant_config(tenant_id)
            .await
            .unwrap()
            .expect("config should exist");
        assert_eq!(
            retrieved.security_thresholds.get("alert_min_score"),
            Some(&80.0)
        );
        assert_eq!(retrieved.feature_flags.get("enable_pii"), Some(&true));

        // Update config
        let mut updated = config.clone();
        updated
            .feature_flags
            .insert("enable_pii".to_string(), false);
        repo.upsert_tenant_config(&updated).await.unwrap();

        let after = repo
            .get_tenant_config(tenant_id)
            .await
            .unwrap()
            .expect("config should exist");
        assert_eq!(after.feature_flags.get("enable_pii"), Some(&false));
    }

    #[tokio::test]
    async fn test_audit_events() {
        let repo = test_metadata().await;
        let tenant_id = TenantId::new();

        let event1 = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id,
            event_type: "config_changed".to_string(),
            actor: "admin".to_string(),
            resource: "tenant_config".to_string(),
            data: serde_json::json!({"field": "enable_pii", "old": false, "new": true}),
            timestamp: Utc::now() - chrono::Duration::minutes(5),
        };
        let event2 = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id,
            event_type: "tenant_created".to_string(),
            actor: "system".to_string(),
            resource: "tenant".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
        };

        repo.record_audit_event(&event1).await.unwrap();
        repo.record_audit_event(&event2).await.unwrap();

        // Query all
        let all = repo
            .query_audit_events(&AuditQuery::new(tenant_id))
            .await
            .unwrap();
        assert_eq!(all.len(), 2);

        // Query by type
        let config_events = repo
            .query_audit_events(
                &AuditQuery::new(tenant_id).with_event_type("config_changed".to_string()),
            )
            .await
            .unwrap();
        assert_eq!(config_events.len(), 1);
        assert_eq!(config_events[0].event_type, "config_changed");
        assert_eq!(config_events[0].actor, "admin");

        // Query with limit
        let limited = repo
            .query_audit_events(&AuditQuery::new(tenant_id).with_limit(1))
            .await
            .unwrap();
        assert_eq!(limited.len(), 1);
    }

    #[tokio::test]
    async fn test_metadata_health_check() {
        let repo = test_metadata().await;
        assert!(repo.health_check().await.is_ok());
    }
}
