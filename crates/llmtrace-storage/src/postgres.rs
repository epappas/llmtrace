//! PostgreSQL storage backend for metadata (tenants, configs, audit events).
//!
//! Provides [`PostgresMetadataRepository`] — a production-grade implementation
//! of [`MetadataRepository`] backed by PostgreSQL, using native JSONB, UUID,
//! and TIMESTAMPTZ column types.
//!
//! Gated behind the `postgres` Cargo feature.

use async_trait::async_trait;
use llmtrace_core::{
    ApiKeyRecord, ApiKeyRole, AuditEvent, AuditQuery, LLMTraceError, MetadataRepository, Result,
    Tenant, TenantConfig, TenantId,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Schema migrations — now driven by versioned SQL files via migration runner
// ---------------------------------------------------------------------------

/// Run versioned PostgreSQL migrations against the given pool.
async fn run_migrations(pool: &PgPool) -> Result<()> {
    crate::migration::run_pg_migrations(pool).await
}

// ===========================================================================
// PostgresMetadataRepository
// ===========================================================================

/// PostgreSQL-backed metadata repository for tenants, configurations, and audit events.
///
/// Uses native PostgreSQL types — `UUID` for identifiers, `TIMESTAMPTZ` for
/// timestamps, and `JSONB` for semi-structured data — providing efficient
/// indexing and querying in production environments.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> llmtrace_core::Result<()> {
/// use llmtrace_core::MetadataRepository;
/// let repo = llmtrace_storage::PostgresMetadataRepository::new(
///     "postgres://user:pass@localhost/llmtrace",
/// ).await?;
/// repo.health_check().await?;
/// # Ok(())
/// # }
/// ```
pub struct PostgresMetadataRepository {
    pool: PgPool,
}

impl PostgresMetadataRepository {
    /// Connect to a PostgreSQL database and run schema migrations.
    ///
    /// The `database_url` should be a full PostgreSQL connection string,
    /// e.g. `postgres://user:pass@localhost/llmtrace`.
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to connect to PostgreSQL: {e}")))?;

        run_migrations(&pool).await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl MetadataRepository for PostgresMetadataRepository {
    async fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenants (id, name, api_token, plan, created_at, config)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant.id.0)
        .bind(&tenant.name)
        .bind(&tenant.api_token)
        .bind(&tenant.plan)
        .bind(tenant.created_at)
        .bind(&tenant.config)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to create tenant: {e}")))?;

        Ok(())
    }

    async fn get_tenant(&self, id: TenantId) -> Result<Option<Tenant>> {
        let row =
            sqlx::query("SELECT id, name, api_token, plan, created_at, config FROM tenants WHERE id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to get tenant: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(Tenant {
            id: TenantId(row.get::<Uuid, _>("id")),
            name: row.get("name"),
            api_token: row.get::<Option<String>, _>("api_token").unwrap_or_default(),
            plan: row.get("plan"),
            created_at: row.get("created_at"),
            config: row.get("config"),
        }))
    }

    async fn get_tenant_by_token(&self, token: &str) -> Result<Option<Tenant>> {
        let row =
            sqlx::query("SELECT id, name, api_token, plan, created_at, config FROM tenants WHERE api_token = $1")
                .bind(token)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| LLMTraceError::Storage(format!("Failed to get tenant by token: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(Tenant {
            id: TenantId(row.get::<Uuid, _>("id")),
            name: row.get("name"),
            api_token: row.get::<Option<String>, _>("api_token").unwrap_or_default(),
            plan: row.get("plan"),
            created_at: row.get("created_at"),
            config: row.get("config"),
        }))
    }

    async fn update_tenant(&self, tenant: &Tenant) -> Result<()> {
        let result =
            sqlx::query("UPDATE tenants SET name = $1, plan = $2, config = $3, api_token = $4 WHERE id = $5")
                .bind(&tenant.name)
                .bind(&tenant.plan)
                .bind(&tenant.config)
                .bind(&tenant.api_token)
                .bind(tenant.id.0)
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
        let rows = sqlx::query(
            "SELECT id, name, api_token, plan, created_at, config FROM tenants ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to list tenants: {e}")))?;

        Ok(rows
            .iter()
            .map(|row| Tenant {
                id: TenantId(row.get::<Uuid, _>("id")),
                name: row.get("name"),
                api_token: row.get::<Option<String>, _>("api_token").unwrap_or_default(),
                plan: row.get("plan"),
                created_at: row.get("created_at"),
                config: row.get("config"),
            })
            .collect())
    }

    async fn delete_tenant(&self, id: TenantId) -> Result<()> {
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to delete tenant: {e}")))?;
        Ok(())
    }

    async fn get_tenant_config(&self, tenant_id: TenantId) -> Result<Option<TenantConfig>> {
        let row = sqlx::query(
            "SELECT tenant_id, security_thresholds, feature_flags, monitoring_scope, rate_limit_rpm, monthly_budget
             FROM tenant_configs WHERE tenant_id = $1",
        )
        .bind(tenant_id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to get tenant config: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let thresholds_json: serde_json::Value = row.get("security_thresholds");
        let flags_json: serde_json::Value = row.get("feature_flags");
        let monitoring_scope_str: String = row.get("monitoring_scope");
        let rate_limit_rpm: Option<i32> = row.get("rate_limit_rpm");
        let monthly_budget: Option<f64> = row.get("monthly_budget");

        let security_thresholds: HashMap<String, f64> = serde_json::from_value(thresholds_json)
            .map_err(|e| {
                LLMTraceError::Storage(format!("Invalid security_thresholds JSON: {e}"))
            })?;
        let feature_flags: HashMap<String, bool> = serde_json::from_value(flags_json)
            .map_err(|e| LLMTraceError::Storage(format!("Invalid feature_flags JSON: {e}")))?;
        let monitoring_scope: llmtrace_core::MonitoringScope = monitoring_scope_str.parse().map_err(|e| {
            LLMTraceError::Storage(format!("Invalid monitoring_scope value: {e}"))
        })?;

        Ok(Some(TenantConfig {
            tenant_id: TenantId(row.get::<Uuid, _>("tenant_id")),
            security_thresholds,
            feature_flags,
            monitoring_scope,
            rate_limit_rpm: rate_limit_rpm.map(|v| v as u32),
            monthly_budget,
        }))
    }

    async fn upsert_tenant_config(&self, config: &TenantConfig) -> Result<()> {
        let thresholds_json = serde_json::to_value(&config.security_thresholds)
            .map_err(|e| LLMTraceError::Storage(format!("serialize thresholds: {e}")))?;
        let flags_json = serde_json::to_value(&config.feature_flags)
            .map_err(|e| LLMTraceError::Storage(format!("serialize feature_flags: {e}")))?;

        sqlx::query(
            "INSERT INTO tenant_configs (tenant_id, security_thresholds, feature_flags, monitoring_scope, rate_limit_rpm, monthly_budget)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id) DO UPDATE SET
                security_thresholds = EXCLUDED.security_thresholds,
                feature_flags = EXCLUDED.feature_flags,
                monitoring_scope = EXCLUDED.monitoring_scope,
                rate_limit_rpm = EXCLUDED.rate_limit_rpm,
                monthly_budget = EXCLUDED.monthly_budget",
        )
        .bind(config.tenant_id.0)
        .bind(&thresholds_json)
        .bind(&flags_json)
        .bind(config.monitoring_scope.to_string())
        .bind(config.rate_limit_rpm.map(|v| v as i32))
        .bind(config.monthly_budget)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to upsert tenant config: {e}")))?;

        Ok(())
    }

    async fn record_audit_event(&self, event: &AuditEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_events (id, tenant_id, event_type, actor, resource, data, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(event.id)
        .bind(event.tenant_id.0)
        .bind(&event.event_type)
        .bind(&event.actor)
        .bind(&event.resource)
        .bind(&event.data)
        .bind(event.timestamp)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to record audit event: {e}")))?;

        Ok(())
    }

    async fn query_audit_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        // Build a dynamic query with bind parameters.
        // We construct the SQL string with numbered placeholders and collect
        // bind values in order, using sqlx's raw query + manual binding.
        let mut sql = String::from(
            "SELECT id, tenant_id, event_type, actor, resource, data, timestamp
             FROM audit_events WHERE tenant_id = $1",
        );
        let mut param_idx: usize = 2;

        // We'll track which optional filters are active.
        let has_event_type = query.event_type.is_some();
        let has_start_time = query.start_time.is_some();
        let has_end_time = query.end_time.is_some();
        let has_limit = query.limit.is_some();
        let has_offset = query.offset.is_some();

        let event_type_idx;
        let start_time_idx;
        let end_time_idx;
        let limit_idx;
        let offset_idx;

        if has_event_type {
            event_type_idx = param_idx;
            sql.push_str(&format!(" AND event_type = ${event_type_idx}"));
            param_idx += 1;
        } else {
            event_type_idx = 0;
        }
        if has_start_time {
            start_time_idx = param_idx;
            sql.push_str(&format!(" AND timestamp >= ${start_time_idx}"));
            param_idx += 1;
        } else {
            start_time_idx = 0;
        }
        if has_end_time {
            end_time_idx = param_idx;
            sql.push_str(&format!(" AND timestamp <= ${end_time_idx}"));
            param_idx += 1;
        } else {
            end_time_idx = 0;
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if has_limit {
            limit_idx = param_idx;
            sql.push_str(&format!(" LIMIT ${limit_idx}"));
            param_idx += 1;
        } else {
            limit_idx = 0;
        }
        if has_offset {
            offset_idx = param_idx;
            sql.push_str(&format!(" OFFSET ${offset_idx}"));
            // param_idx += 1; // not needed after last use
        } else {
            offset_idx = 0;
        }

        // Suppress unused-variable warnings for bookkeeping indices.
        let _ = (
            event_type_idx,
            start_time_idx,
            end_time_idx,
            limit_idx,
            offset_idx,
            param_idx,
        );

        // Bind parameters in the exact order they were numbered.
        let mut q = sqlx::query(&sql).bind(query.tenant_id.0);

        if let Some(ref event_type) = query.event_type {
            q = q.bind(event_type);
        }
        if let Some(ref start) = query.start_time {
            q = q.bind(start);
        }
        if let Some(ref end) = query.end_time {
            q = q.bind(end);
        }
        if let Some(limit) = query.limit {
            q = q.bind(limit as i64);
        }
        if let Some(offset) = query.offset {
            q = q.bind(offset as i64);
        }

        let rows = q
            .fetch_all(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query audit events: {e}")))?;

        Ok(rows
            .iter()
            .map(|row| AuditEvent {
                id: row.get::<Uuid, _>("id"),
                tenant_id: TenantId(row.get::<Uuid, _>("tenant_id")),
                event_type: row.get("event_type"),
                actor: row.get("actor"),
                resource: row.get("resource"),
                data: row.get("data"),
                timestamp: row.get("timestamp"),
            })
            .collect())
    }

    async fn create_api_key(&self, key: &ApiKeyRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, role, created_at, revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(key.id)
        .bind(key.tenant_id.0)
        .bind(&key.name)
        .bind(&key.key_hash)
        .bind(&key.key_prefix)
        .bind(key.role.to_string())
        .bind(key.created_at)
        .bind(key.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to create API key: {e}")))?;
        Ok(())
    }

    async fn get_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKeyRecord>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, key_hash, key_prefix, role, created_at, revoked_at
             FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to look up API key: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let role_str: String = row.get("role");
        Ok(Some(ApiKeyRecord {
            id: row.get::<Uuid, _>("id"),
            tenant_id: TenantId(row.get::<Uuid, _>("tenant_id")),
            name: row.get("name"),
            key_hash: row.get("key_hash"),
            key_prefix: row.get("key_prefix"),
            role: role_str
                .parse::<ApiKeyRole>()
                .map_err(|e| LLMTraceError::Storage(format!("Invalid API key role: {e}")))?,
            created_at: row.get("created_at"),
            revoked_at: row.get("revoked_at"),
        }))
    }

    async fn list_api_keys(&self, tenant_id: TenantId) -> Result<Vec<ApiKeyRecord>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, key_hash, key_prefix, role, created_at, revoked_at
             FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id.0)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to list API keys: {e}")))?;

        rows.iter()
            .map(|row| {
                let role_str: String = row.get("role");
                Ok(ApiKeyRecord {
                    id: row.get::<Uuid, _>("id"),
                    tenant_id: TenantId(row.get::<Uuid, _>("tenant_id")),
                    name: row.get("name"),
                    key_hash: row.get("key_hash"),
                    key_prefix: row.get("key_prefix"),
                    role: role_str.parse::<ApiKeyRole>().map_err(|e| {
                        LLMTraceError::Storage(format!("Invalid API key role: {e}"))
                    })?,
                    created_at: row.get("created_at"),
                    revoked_at: row.get("revoked_at"),
                })
            })
            .collect()
    }

    async fn revoke_api_key(&self, key_id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(key_id)
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to revoke API key: {e}")))?;

        Ok(result.rows_affected() > 0)
    }

    async fn store_report(&self, report: &llmtrace_core::ComplianceReportRecord) -> Result<()> {
        sqlx::query(
            "INSERT INTO compliance_reports
             (id, tenant_id, report_type, status, period_start, period_end, created_at, completed_at, content, error)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT(id) DO UPDATE SET
                status = EXCLUDED.status,
                completed_at = EXCLUDED.completed_at,
                content = EXCLUDED.content,
                error = EXCLUDED.error",
        )
        .bind(report.id)
        .bind(report.tenant_id.0)
        .bind(&report.report_type)
        .bind(&report.status)
        .bind(report.period_start)
        .bind(report.period_end)
        .bind(report.created_at)
        .bind(report.completed_at)
        .bind(&report.content)
        .bind(report.error.as_deref())
        .execute(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to store compliance report: {e}")))?;

        Ok(())
    }

    async fn get_report(
        &self,
        report_id: Uuid,
    ) -> Result<Option<llmtrace_core::ComplianceReportRecord>> {
        use sqlx::Row;
        let row = sqlx::query("SELECT * FROM compliance_reports WHERE id = $1")
            .bind(report_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to get report: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let content: Option<serde_json::Value> = row.get("content");

        Ok(Some(llmtrace_core::ComplianceReportRecord {
            id: row.get("id"),
            tenant_id: llmtrace_core::TenantId(row.get("tenant_id")),
            report_type: row.get("report_type"),
            status: row.get("status"),
            period_start: row.get("period_start"),
            period_end: row.get("period_end"),
            created_at: row.get("created_at"),
            completed_at: row.get("completed_at"),
            content,
            error: row.get("error"),
        }))
    }

    async fn list_reports(
        &self,
        query: &llmtrace_core::ReportQuery,
    ) -> Result<Vec<llmtrace_core::ComplianceReportRecord>> {
        use sqlx::Row;
        let limit = query.limit.unwrap_or(50) as i64;
        let offset = query.offset.unwrap_or(0) as i64;

        let rows = sqlx::query(
            "SELECT * FROM compliance_reports WHERE tenant_id = $1
             ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(query.tenant_id.0)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to list reports: {e}")))?;

        rows.iter()
            .map(|row| {
                let content: Option<serde_json::Value> = row.get("content");

                Ok(llmtrace_core::ComplianceReportRecord {
                    id: row.get("id"),
                    tenant_id: llmtrace_core::TenantId(row.get("tenant_id")),
                    report_type: row.get("report_type"),
                    status: row.get("status"),
                    period_start: row.get("period_start"),
                    period_end: row.get("period_end"),
                    created_at: row.get("created_at"),
                    completed_at: row.get("completed_at"),
                    content,
                    error: row.get("error"),
                })
            })
            .collect()
    }

    async fn health_check(&self) -> Result<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
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
    use chrono::Utc;
    use std::env;

    /// Return a [`PostgresMetadataRepository`] connected to the test instance,
    /// or panic if `LLMTRACE_POSTGRES_URL` is not set.
    async fn test_repo() -> PostgresMetadataRepository {
        let url = env::var("LLMTRACE_POSTGRES_URL")
            .expect("LLMTRACE_POSTGRES_URL must be set for PostgreSQL tests");
        PostgresMetadataRepository::new(&url).await.unwrap()
    }

    /// Create a test tenant with a unique ID.
    fn make_tenant() -> Tenant {
        Tenant {
            id: TenantId::new(),
            name: "Test Corp".to_string(),
            plan: "pro".to_string(),
            created_at: Utc::now(),
            config: serde_json::json!({"max_traces_per_day": 10000}),
        }
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_create_tenant_get_tenant_roundtrip() {
        let repo = test_repo().await;
        let tenant = make_tenant();

        repo.create_tenant(&tenant).await.unwrap();

        let retrieved = repo
            .get_tenant(tenant.id)
            .await
            .unwrap()
            .expect("tenant should exist");

        assert_eq!(retrieved.id, tenant.id);
        assert_eq!(retrieved.name, "Test Corp");
        assert_eq!(retrieved.plan, "pro");
        assert_eq!(
            retrieved.config,
            serde_json::json!({"max_traces_per_day": 10000})
        );
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_update_tenant_changes_fields() {
        let repo = test_repo().await;
        let mut tenant = make_tenant();

        repo.create_tenant(&tenant).await.unwrap();

        tenant.name = "Updated Corp".to_string();
        tenant.plan = "enterprise".to_string();
        tenant.config = serde_json::json!({"max_traces_per_day": 50000});

        repo.update_tenant(&tenant).await.unwrap();

        let retrieved = repo.get_tenant(tenant.id).await.unwrap().unwrap();
        assert_eq!(retrieved.name, "Updated Corp");
        assert_eq!(retrieved.plan, "enterprise");
        assert_eq!(
            retrieved.config,
            serde_json::json!({"max_traces_per_day": 50000})
        );
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_list_tenants_returns_all() {
        let repo = test_repo().await;
        let tenant_a = make_tenant();
        let tenant_b = make_tenant();

        repo.create_tenant(&tenant_a).await.unwrap();
        repo.create_tenant(&tenant_b).await.unwrap();

        let all = repo.list_tenants().await.unwrap();

        let ids: Vec<TenantId> = all.iter().map(|t| t.id).collect();
        assert!(ids.contains(&tenant_a.id));
        assert!(ids.contains(&tenant_b.id));
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_delete_tenant_removes_tenant() {
        let repo = test_repo().await;
        let tenant = make_tenant();

        repo.create_tenant(&tenant).await.unwrap();
        assert!(repo.get_tenant(tenant.id).await.unwrap().is_some());

        repo.delete_tenant(tenant.id).await.unwrap();
        assert!(repo.get_tenant(tenant.id).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_upsert_tenant_config_create_and_update() {
        let repo = test_repo().await;
        let tenant = make_tenant();
        repo.create_tenant(&tenant).await.unwrap();

        // Create config
        let mut thresholds = HashMap::new();
        thresholds.insert("alert_min_score".to_string(), 80.0);
        let mut flags = HashMap::new();
        flags.insert("enable_pii_detection".to_string(), true);

        let config = TenantConfig {
            tenant_id: tenant.id,
            security_thresholds: thresholds,
            feature_flags: flags,
            monitoring_scope: llmtrace_core::MonitoringScope::Hybrid,
            rate_limit_rpm: None,
            monthly_budget: None,
        };
        repo.upsert_tenant_config(&config).await.unwrap();

        let retrieved = repo
            .get_tenant_config(tenant.id)
            .await
            .unwrap()
            .expect("config should exist");
        assert_eq!(retrieved.tenant_id, tenant.id);
        assert!((retrieved.security_thresholds["alert_min_score"] - 80.0).abs() < f64::EPSILON);
        assert!(retrieved.feature_flags["enable_pii_detection"]);

        // Update config
        let mut updated_thresholds = HashMap::new();
        updated_thresholds.insert("alert_min_score".to_string(), 90.0);
        let mut updated_flags = HashMap::new();
        updated_flags.insert("enable_pii_detection".to_string(), false);
        updated_flags.insert("enable_cost_tracking".to_string(), true);

        let updated_config = TenantConfig {
            tenant_id: tenant.id,
            security_thresholds: updated_thresholds,
            feature_flags: updated_flags,
            monitoring_scope: llmtrace_core::MonitoringScope::Hybrid,
            rate_limit_rpm: None,
            monthly_budget: None,
        };
        repo.upsert_tenant_config(&updated_config).await.unwrap();

        let retrieved2 = repo.get_tenant_config(tenant.id).await.unwrap().unwrap();
        assert!((retrieved2.security_thresholds["alert_min_score"] - 90.0).abs() < f64::EPSILON);
        assert!(!retrieved2.feature_flags["enable_pii_detection"]);
        assert!(retrieved2.feature_flags["enable_cost_tracking"]);
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_record_audit_event_and_query() {
        let repo = test_repo().await;
        let tenant = make_tenant();
        repo.create_tenant(&tenant).await.unwrap();

        let event = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            event_type: "config_changed".to_string(),
            actor: "admin@example.com".to_string(),
            resource: "tenant_config".to_string(),
            data: serde_json::json!({"field": "plan", "old": "free", "new": "pro"}),
            timestamp: Utc::now(),
        };
        repo.record_audit_event(&event).await.unwrap();

        let query = AuditQuery::new(tenant.id);
        let results = repo.query_audit_events(&query).await.unwrap();

        assert!(!results.is_empty());
        let found = results.iter().find(|e| e.id == event.id);
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.event_type, "config_changed");
        assert_eq!(found.actor, "admin@example.com");
        assert_eq!(found.resource, "tenant_config");
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_audit_query_with_event_type_filter() {
        let repo = test_repo().await;
        let tenant = make_tenant();
        repo.create_tenant(&tenant).await.unwrap();

        let event_a = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            event_type: "config_changed".to_string(),
            actor: "admin".to_string(),
            resource: "config".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
        };
        let event_b = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            event_type: "tenant_created".to_string(),
            actor: "system".to_string(),
            resource: "tenant".to_string(),
            data: serde_json::json!({}),
            timestamp: Utc::now(),
        };

        repo.record_audit_event(&event_a).await.unwrap();
        repo.record_audit_event(&event_b).await.unwrap();

        let query = AuditQuery::new(tenant.id).with_event_type("config_changed".to_string());
        let results = repo.query_audit_events(&query).await.unwrap();

        assert!(results.iter().all(|e| e.event_type == "config_changed"));
        assert!(results.iter().any(|e| e.id == event_a.id));
        assert!(!results.iter().any(|e| e.id == event_b.id));
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_audit_query_with_time_range_filter() {
        let repo = test_repo().await;
        let tenant = make_tenant();
        repo.create_tenant(&tenant).await.unwrap();

        let old_time = Utc::now() - chrono::Duration::hours(2);
        let recent_time = Utc::now();

        let old_event = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            event_type: "old_event".to_string(),
            actor: "admin".to_string(),
            resource: "config".to_string(),
            data: serde_json::json!({}),
            timestamp: old_time,
        };
        let recent_event = AuditEvent {
            id: Uuid::new_v4(),
            tenant_id: tenant.id,
            event_type: "recent_event".to_string(),
            actor: "admin".to_string(),
            resource: "config".to_string(),
            data: serde_json::json!({}),
            timestamp: recent_time,
        };

        repo.record_audit_event(&old_event).await.unwrap();
        repo.record_audit_event(&recent_event).await.unwrap();

        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let query = AuditQuery::new(tenant.id).with_time_range(one_hour_ago, Utc::now());
        let results = repo.query_audit_events(&query).await.unwrap();

        assert!(results.iter().any(|e| e.id == recent_event.id));
        assert!(!results.iter().any(|e| e.id == old_event.id));
    }

    #[tokio::test]
    #[ignore = "requires a running PostgreSQL instance"]
    async fn test_health_check_succeeds() {
        let repo = test_repo().await;
        assert!(repo.health_check().await.is_ok());
    }
}
