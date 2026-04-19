//! Persistence implementations for [`JudgeVerdict`] records (issue #43).
//!
//! The in-memory backend is always available and used by the Memory
//! and Lite storage profiles. Production deployments typically use
//! the ClickHouse backend so the Pipeline Learning service can run
//! large time-range scans over verdicts.

use async_trait::async_trait;
use llmtrace_core::{JudgeVerdict, JudgeVerdictQuery, JudgeVerdictStore, Result};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// In-memory backend (always available)
// ---------------------------------------------------------------------------

/// In-memory judge verdict store. Not intended for production use;
/// data is lost when the struct is dropped.
pub struct InMemoryJudgeVerdictStore {
    verdicts: RwLock<Vec<JudgeVerdict>>,
}

impl Default for InMemoryJudgeVerdictStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryJudgeVerdictStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            verdicts: RwLock::new(Vec::new()),
        }
    }
}

#[async_trait]
impl JudgeVerdictStore for InMemoryJudgeVerdictStore {
    async fn insert_verdict(&self, verdict: &JudgeVerdict) -> Result<()> {
        self.verdicts.write().await.push(verdict.clone());
        Ok(())
    }

    async fn query_verdicts(&self, query: &JudgeVerdictQuery) -> Result<Vec<JudgeVerdict>> {
        let guard = self.verdicts.read().await;
        let mut out: Vec<JudgeVerdict> = guard
            .iter()
            .filter(|v| matches_query(v, query))
            .cloned()
            .collect();
        out.sort_by_key(|v| std::cmp::Reverse(v.created_at));
        if let Some(limit) = query.limit {
            out.truncate(limit as usize);
        }
        Ok(out)
    }

    async fn health_check(&self) -> Result<()> {
        Ok(())
    }
}

fn matches_query(verdict: &JudgeVerdict, query: &JudgeVerdictQuery) -> bool {
    if let Some(t) = query.tenant_id {
        if verdict.tenant_id != t {
            return false;
        }
    }
    if let Some(trace_id) = query.trace_id {
        if verdict.trace_id != trace_id {
            return false;
        }
    }
    if let Some(since) = query.since {
        if verdict.created_at < since {
            return false;
        }
    }
    if let Some(until) = query.until {
        if verdict.created_at > until {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// ClickHouse backend
// ---------------------------------------------------------------------------

#[cfg(feature = "clickhouse")]
mod clickhouse_impl {
    use super::*;
    use clickhouse::{Client, Row};
    use llmtrace_core::{JudgeMode, LLMTraceError, TenantId};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    /// ClickHouse-backed judge verdict store.
    ///
    /// Stores verdicts in a `judge_verdicts` MergeTree table ordered by
    /// `(tenant_id, created_at)` with a 90-day TTL. See
    /// `docs/architecture/LLM_JUDGE.md` section 5.7 for the full schema.
    pub struct ClickHouseJudgeVerdictStore {
        client: Client,
        database: String,
    }

    impl ClickHouseJudgeVerdictStore {
        /// Construct the store and run DDL migrations (idempotent
        /// `CREATE TABLE IF NOT EXISTS`).
        pub async fn new(url: &str, database: &str) -> Result<Self> {
            let client = Client::default()
                .with_url(url)
                .with_database(database);
            let store = Self {
                client,
                database: database.to_string(),
            };
            store.run_migrations().await?;
            Ok(store)
        }

        async fn run_migrations(&self) -> Result<()> {
            let db = &self.database;
            let ddl = format!(
                "CREATE TABLE IF NOT EXISTS `{db}`.judge_verdicts (
                    id UUID,
                    trace_id UUID,
                    tenant_id UUID,
                    is_threat Boolean,
                    category LowCardinality(String),
                    confidence Float64,
                    security_score UInt8,
                    recommended_action LowCardinality(String),
                    reasoning String CODEC(ZSTD(1)),
                    mode LowCardinality(String),
                    model_used LowCardinality(String),
                    latency_ms UInt64,
                    prompt_tokens Nullable(UInt32),
                    completion_tokens Nullable(UInt32),
                    created_at DateTime64(3)
                ) ENGINE = MergeTree()
                ORDER BY (tenant_id, created_at)
                TTL toDateTime(created_at) + INTERVAL 90 DAY"
            );
            self.client
                .query(&ddl)
                .execute()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("judge_verdicts DDL: {e}")))?;
            Ok(())
        }
    }

    /// Row adapter matching the ClickHouse schema. Mirrors
    /// [`JudgeVerdict`] but with provider-specific types for
    /// enum-as-string and date-time values.
    #[derive(Row, Serialize, Deserialize)]
    struct JudgeVerdictRow {
        #[serde(with = "clickhouse::serde::uuid")]
        id: Uuid,
        #[serde(with = "clickhouse::serde::uuid")]
        trace_id: Uuid,
        #[serde(with = "clickhouse::serde::uuid")]
        tenant_id: Uuid,
        is_threat: bool,
        category: String,
        confidence: f64,
        security_score: u8,
        recommended_action: String,
        reasoning: String,
        mode: String,
        model_used: String,
        latency_ms: u64,
        prompt_tokens: Option<u32>,
        completion_tokens: Option<u32>,
        #[serde(with = "clickhouse::serde::chrono::datetime64::millis")]
        created_at: chrono::DateTime<chrono::Utc>,
    }

    impl From<&JudgeVerdict> for JudgeVerdictRow {
        fn from(v: &JudgeVerdict) -> Self {
            Self {
                id: v.id,
                trace_id: v.trace_id,
                tenant_id: v.tenant_id.0,
                is_threat: v.is_threat,
                category: v.category.clone(),
                confidence: v.confidence,
                security_score: v.security_score,
                recommended_action: v.recommended_action.clone(),
                reasoning: v.reasoning.clone(),
                mode: v.mode.as_str().to_string(),
                model_used: v.model_used.clone(),
                latency_ms: v.latency_ms,
                prompt_tokens: v.prompt_tokens,
                completion_tokens: v.completion_tokens,
                created_at: v.created_at,
            }
        }
    }

    impl TryFrom<JudgeVerdictRow> for JudgeVerdict {
        type Error = LLMTraceError;
        fn try_from(r: JudgeVerdictRow) -> std::result::Result<Self, Self::Error> {
            let mode = match r.mode.as_str() {
                "inline" => JudgeMode::Inline,
                "async" => JudgeMode::Async,
                other => {
                    return Err(LLMTraceError::Storage(format!(
                        "unknown judge mode in row: {other}"
                    )))
                }
            };
            Ok(JudgeVerdict {
                id: r.id,
                trace_id: r.trace_id,
                tenant_id: TenantId(r.tenant_id),
                is_threat: r.is_threat,
                category: r.category,
                confidence: r.confidence,
                security_score: r.security_score,
                recommended_action: r.recommended_action,
                reasoning: r.reasoning,
                mode,
                model_used: r.model_used,
                latency_ms: r.latency_ms,
                prompt_tokens: r.prompt_tokens,
                completion_tokens: r.completion_tokens,
                created_at: r.created_at,
            })
        }
    }

    #[async_trait]
    impl JudgeVerdictStore for ClickHouseJudgeVerdictStore {
        async fn insert_verdict(&self, verdict: &JudgeVerdict) -> Result<()> {
            let db = &self.database;
            let mut insert = self
                .client
                .insert::<JudgeVerdictRow>(&format!("`{db}`.judge_verdicts"))
                .await
                .map_err(|e| LLMTraceError::Storage(format!("judge insert prepare: {e}")))?;
            insert
                .write(&JudgeVerdictRow::from(verdict))
                .await
                .map_err(|e| LLMTraceError::Storage(format!("judge insert write: {e}")))?;
            insert
                .end()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("judge insert end: {e}")))?;
            Ok(())
        }

        async fn query_verdicts(&self, query: &JudgeVerdictQuery) -> Result<Vec<JudgeVerdict>> {
            let db = &self.database;
            let mut conditions: Vec<String> = Vec::new();
            if let Some(t) = query.tenant_id {
                conditions.push(format!("tenant_id = toUUID('{}')", t.0));
            }
            if let Some(trace_id) = query.trace_id {
                conditions.push(format!("trace_id = toUUID('{trace_id}')"));
            }
            if let Some(since) = query.since {
                conditions.push(format!(
                    "created_at >= toDateTime64('{}', 3)",
                    since.format("%Y-%m-%d %H:%M:%S%.3f")
                ));
            }
            if let Some(until) = query.until {
                conditions.push(format!(
                    "created_at <= toDateTime64('{}', 3)",
                    until.format("%Y-%m-%d %H:%M:%S%.3f")
                ));
            }
            let where_clause = if conditions.is_empty() {
                String::new()
            } else {
                format!("WHERE {}", conditions.join(" AND "))
            };
            let limit_clause = match query.limit {
                Some(n) => format!("LIMIT {n}"),
                None => String::new(),
            };
            let sql = format!(
                "SELECT id, trace_id, tenant_id, is_threat, category, confidence, \
                 security_score, recommended_action, reasoning, mode, model_used, \
                 latency_ms, prompt_tokens, completion_tokens, created_at \
                 FROM `{db}`.judge_verdicts {where_clause} \
                 ORDER BY created_at DESC {limit_clause}"
            );
            let rows: Vec<JudgeVerdictRow> = self
                .client
                .query(&sql)
                .fetch_all()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("judge query: {e}")))?;
            rows.into_iter().map(JudgeVerdict::try_from).collect()
        }

        async fn health_check(&self) -> Result<()> {
            self.client
                .query("SELECT 1")
                .execute()
                .await
                .map_err(|e| LLMTraceError::Storage(format!("ClickHouse health: {e}")))?;
            Ok(())
        }
    }
}

#[cfg(feature = "clickhouse")]
pub use clickhouse_impl::ClickHouseJudgeVerdictStore;

// ---------------------------------------------------------------------------
// Postgres backend
// ---------------------------------------------------------------------------

#[cfg(feature = "postgres")]
mod postgres_impl {
    use super::*;
    use chrono::{DateTime, Utc};
    use llmtrace_core::{JudgeMode, LLMTraceError, TenantId};
    use sqlx::{postgres::PgPoolOptions, PgPool, Row};

    /// PostgreSQL-backed judge verdict store. See
    /// `docs/architecture/LLM_JUDGE.md` section 5.7 for the schema.
    pub struct PostgresJudgeVerdictStore {
        pool: PgPool,
    }

    impl PostgresJudgeVerdictStore {
        pub async fn new(url: &str) -> Result<Self> {
            let pool = PgPoolOptions::new()
                .max_connections(5)
                .connect(url)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Postgres judge connect: {e}")))?;
            let store = Self { pool };
            store.run_migrations().await?;
            Ok(store)
        }

        #[must_use]
        pub fn from_pool(pool: PgPool) -> Self {
            Self { pool }
        }

        async fn run_migrations(&self) -> Result<()> {
            sqlx::query(include_str!(
                "../migrations/postgres/006_judge_verdicts.sql"
            ))
            .execute(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("judge_verdicts migration: {e}")))?;
            Ok(())
        }
    }

    fn mode_to_str(m: JudgeMode) -> &'static str {
        m.as_str()
    }

    fn mode_from_str(s: &str) -> Result<JudgeMode> {
        match s {
            "inline" => Ok(JudgeMode::Inline),
            "async" => Ok(JudgeMode::Async),
            other => Err(LLMTraceError::Storage(format!(
                "unknown judge mode in row: {other}"
            ))),
        }
    }

    #[async_trait]
    impl JudgeVerdictStore for PostgresJudgeVerdictStore {
        async fn insert_verdict(&self, v: &JudgeVerdict) -> Result<()> {
            sqlx::query(
                "INSERT INTO judge_verdicts (\
                    id, trace_id, tenant_id, is_threat, category, confidence, \
                    security_score, recommended_action, reasoning, mode, model_used, \
                    latency_ms, prompt_tokens, completion_tokens, created_at) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            )
            .bind(v.id)
            .bind(v.trace_id)
            .bind(v.tenant_id.0)
            .bind(v.is_threat)
            .bind(&v.category)
            .bind(v.confidence)
            .bind(i32::from(v.security_score))
            .bind(&v.recommended_action)
            .bind(&v.reasoning)
            .bind(mode_to_str(v.mode))
            .bind(&v.model_used)
            .bind(i64::try_from(v.latency_ms).unwrap_or(i64::MAX))
            .bind(v.prompt_tokens.map(|t| t as i32))
            .bind(v.completion_tokens.map(|t| t as i32))
            .bind(v.created_at)
            .execute(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("judge insert: {e}")))?;
            Ok(())
        }

        async fn query_verdicts(&self, query: &JudgeVerdictQuery) -> Result<Vec<JudgeVerdict>> {
            // Build dynamic SQL with bound parameters. sqlx-qb is not in
            // use elsewhere in the crate, so we keep this small and
            // explicit.
            let mut sql = String::from(
                "SELECT id, trace_id, tenant_id, is_threat, category, confidence, \
                 security_score, recommended_action, reasoning, mode, model_used, \
                 latency_ms, prompt_tokens, completion_tokens, created_at \
                 FROM judge_verdicts WHERE 1=1",
            );
            if query.tenant_id.is_some() {
                sql.push_str(" AND tenant_id = $1");
            }
            if query.trace_id.is_some() {
                let n = 1 + query.tenant_id.is_some() as i32;
                sql.push_str(&format!(" AND trace_id = ${n}"));
            }
            if query.since.is_some() {
                let n = 1 + query.tenant_id.is_some() as i32 + query.trace_id.is_some() as i32;
                sql.push_str(&format!(" AND created_at >= ${n}"));
            }
            if query.until.is_some() {
                let n = 1 + query.tenant_id.is_some() as i32
                    + query.trace_id.is_some() as i32
                    + query.since.is_some() as i32;
                sql.push_str(&format!(" AND created_at <= ${n}"));
            }
            sql.push_str(" ORDER BY created_at DESC");
            if let Some(limit) = query.limit {
                sql.push_str(&format!(" LIMIT {limit}"));
            }

            let mut q = sqlx::query(&sql);
            if let Some(t) = query.tenant_id {
                q = q.bind(t.0);
            }
            if let Some(trace_id) = query.trace_id {
                q = q.bind(trace_id);
            }
            if let Some(since) = query.since {
                q = q.bind(since);
            }
            if let Some(until) = query.until {
                q = q.bind(until);
            }

            let rows = q
                .fetch_all(&self.pool)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("judge query: {e}")))?;

            rows.into_iter()
                .map(|row| -> Result<JudgeVerdict> {
                    let mode_str: String = row
                        .try_get("mode")
                        .map_err(|e| LLMTraceError::Storage(format!("mode col: {e}")))?;
                    let mode = mode_from_str(&mode_str)?;
                    let security_score_i32: i32 = row
                        .try_get("security_score")
                        .map_err(|e| LLMTraceError::Storage(format!("score col: {e}")))?;
                    let latency_ms_i64: i64 = row
                        .try_get("latency_ms")
                        .map_err(|e| LLMTraceError::Storage(format!("latency col: {e}")))?;
                    let prompt_tokens_i32: Option<i32> = row
                        .try_get("prompt_tokens")
                        .map_err(|e| LLMTraceError::Storage(format!("pt col: {e}")))?;
                    let completion_tokens_i32: Option<i32> = row
                        .try_get("completion_tokens")
                        .map_err(|e| LLMTraceError::Storage(format!("ct col: {e}")))?;

                    Ok(JudgeVerdict {
                        id: row
                            .try_get("id")
                            .map_err(|e| LLMTraceError::Storage(format!("id col: {e}")))?,
                        trace_id: row.try_get("trace_id").map_err(|e| {
                            LLMTraceError::Storage(format!("trace_id col: {e}"))
                        })?,
                        tenant_id: TenantId(row.try_get("tenant_id").map_err(|e| {
                            LLMTraceError::Storage(format!("tenant_id col: {e}"))
                        })?),
                        is_threat: row.try_get("is_threat").map_err(|e| {
                            LLMTraceError::Storage(format!("is_threat col: {e}"))
                        })?,
                        category: row.try_get("category").map_err(|e| {
                            LLMTraceError::Storage(format!("category col: {e}"))
                        })?,
                        confidence: row.try_get("confidence").map_err(|e| {
                            LLMTraceError::Storage(format!("confidence col: {e}"))
                        })?,
                        security_score: u8::try_from(security_score_i32.clamp(0, 255))
                            .unwrap_or(0),
                        recommended_action: row.try_get("recommended_action").map_err(|e| {
                            LLMTraceError::Storage(format!("ra col: {e}"))
                        })?,
                        reasoning: row.try_get("reasoning").map_err(|e| {
                            LLMTraceError::Storage(format!("reasoning col: {e}"))
                        })?,
                        mode,
                        model_used: row.try_get("model_used").map_err(|e| {
                            LLMTraceError::Storage(format!("model_used col: {e}"))
                        })?,
                        latency_ms: u64::try_from(latency_ms_i64.max(0)).unwrap_or(0),
                        prompt_tokens: prompt_tokens_i32.map(|v| v.max(0) as u32),
                        completion_tokens: completion_tokens_i32.map(|v| v.max(0) as u32),
                        created_at: row
                            .try_get::<DateTime<Utc>, _>("created_at")
                            .map_err(|e| LLMTraceError::Storage(format!("ca col: {e}")))?,
                    })
                })
                .collect()
        }

        async fn health_check(&self) -> Result<()> {
            sqlx::query("SELECT 1")
                .execute(&self.pool)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Postgres health: {e}")))?;
            Ok(())
        }
    }
}

#[cfg(feature = "postgres")]
pub use postgres_impl::PostgresJudgeVerdictStore;

// ---------------------------------------------------------------------------
// Tests (InMemory only — ClickHouse/Postgres require running services)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use llmtrace_core::{JudgeMode, TenantId};
    use uuid::Uuid;

    fn make_verdict(tenant: TenantId, category: &str, score: u8) -> JudgeVerdict {
        JudgeVerdict {
            id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            tenant_id: tenant,
            is_threat: score >= 50,
            category: category.to_string(),
            confidence: 0.8,
            security_score: score,
            recommended_action: "block".to_string(),
            reasoning: "test".to_string(),
            mode: JudgeMode::Async,
            model_used: "security-judge-v1".to_string(),
            latency_ms: 100,
            prompt_tokens: Some(50),
            completion_tokens: Some(20),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn in_memory_insert_and_query_roundtrip() {
        let store = InMemoryJudgeVerdictStore::new();
        let tenant = TenantId::new();
        let v = make_verdict(tenant, "prompt_injection", 80);
        store.insert_verdict(&v).await.unwrap();

        let results = store
            .query_verdicts(&JudgeVerdictQuery {
                tenant_id: Some(tenant),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, v.id);
    }

    #[tokio::test]
    async fn in_memory_filters_by_tenant() {
        let store = InMemoryJudgeVerdictStore::new();
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        store
            .insert_verdict(&make_verdict(tenant_a, "jailbreak", 70))
            .await
            .unwrap();
        store
            .insert_verdict(&make_verdict(tenant_b, "benign", 10))
            .await
            .unwrap();

        let out = store
            .query_verdicts(&JudgeVerdictQuery {
                tenant_id: Some(tenant_a),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].tenant_id, tenant_a);
    }

    #[tokio::test]
    async fn in_memory_filters_by_trace_id() {
        let store = InMemoryJudgeVerdictStore::new();
        let tenant = TenantId::new();
        let target_trace = Uuid::new_v4();
        let mut v1 = make_verdict(tenant, "prompt_injection", 60);
        v1.trace_id = target_trace;
        let v2 = make_verdict(tenant, "benign", 5);
        store.insert_verdict(&v1).await.unwrap();
        store.insert_verdict(&v2).await.unwrap();

        let out = store
            .query_verdicts(&JudgeVerdictQuery {
                trace_id: Some(target_trace),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].trace_id, target_trace);
    }

    #[tokio::test]
    async fn in_memory_time_range_filter() {
        let store = InMemoryJudgeVerdictStore::new();
        let tenant = TenantId::new();
        let now = Utc::now();
        let mut old = make_verdict(tenant, "benign", 5);
        old.created_at = now - Duration::hours(2);
        let mut recent = make_verdict(tenant, "jailbreak", 70);
        recent.created_at = now - Duration::minutes(10);
        store.insert_verdict(&old).await.unwrap();
        store.insert_verdict(&recent).await.unwrap();

        let out = store
            .query_verdicts(&JudgeVerdictQuery {
                tenant_id: Some(tenant),
                since: Some(now - Duration::hours(1)),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].category, "jailbreak");
    }

    #[tokio::test]
    async fn in_memory_limit_honors_n() {
        let store = InMemoryJudgeVerdictStore::new();
        let tenant = TenantId::new();
        for i in 0..5 {
            let mut v = make_verdict(tenant, "benign", i);
            v.created_at = Utc::now() + Duration::seconds(i as i64);
            store.insert_verdict(&v).await.unwrap();
        }
        let out = store
            .query_verdicts(&JudgeVerdictQuery {
                tenant_id: Some(tenant),
                limit: Some(2),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(out.len(), 2);
        // Sorted DESC on created_at, so the two most recent are returned.
        assert!(out[0].created_at >= out[1].created_at);
    }

    #[tokio::test]
    async fn in_memory_health_check_always_ok() {
        let store = InMemoryJudgeVerdictStore::new();
        store.health_check().await.unwrap();
    }
}
