//! Database migration management with versioned schemas.
//!
//! Provides a simple, embedded migration runner for SQLite and PostgreSQL.
//! Migration SQL files are embedded at compile time via `include_str!` so they
//! are always available without filesystem access at runtime.
//!
//! Each migration is tracked in a `schema_version` table, applied exactly once,
//! and wrapped in a transaction for safety.

use llmtrace_core::{LLMTraceError, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use sqlx::SqlitePool;
use std::str::FromStr;
use tracing::info;

// ---------------------------------------------------------------------------
// Embedded migration SQL — compiled into the binary
// ---------------------------------------------------------------------------

/// A single versioned migration with its SQL content and description.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Monotonically increasing version number (matches file prefix).
    pub version: i64,
    /// Human-readable description (derived from filename).
    pub description: String,
    /// SQL statements to execute for this migration.
    pub sql: &'static str,
}

/// Embedded SQLite migrations (always available).
pub fn sqlite_migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            description: "initial_schema".to_string(),
            sql: include_str!("../migrations/sqlite/001_initial_schema.sql"),
        },
        Migration {
            version: 2,
            description: "metadata_tables".to_string(),
            sql: include_str!("../migrations/sqlite/002_metadata_tables.sql"),
        },
        Migration {
            version: 3,
            description: "add_agent_actions".to_string(),
            sql: include_str!("../migrations/sqlite/003_add_agent_actions.sql"),
        },
        Migration {
            version: 4,
            description: "compliance_reports".to_string(),
            sql: include_str!("../migrations/sqlite/004_compliance_reports.sql"),
        },
    ]
}

/// Embedded PostgreSQL migrations (only available with `postgres` feature).
#[cfg(feature = "postgres")]
pub fn postgres_migrations() -> Vec<Migration> {
    vec![Migration {
        version: 1,
        description: "initial_schema".to_string(),
        sql: include_str!("../migrations/postgres/001_initial_schema.sql"),
    }]
}

// ---------------------------------------------------------------------------
// SQLite migration runner
// ---------------------------------------------------------------------------

/// Create the `schema_version` tracking table if it does not exist (SQLite).
async fn ensure_sqlite_version_table(pool: &sqlx::SqlitePool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now')),
            description TEXT
        )",
    )
    .execute(pool)
    .await
    .map_err(|e| LLMTraceError::Storage(format!("Failed to create schema_version table: {e}")))?;
    Ok(())
}

/// Return the highest applied migration version for SQLite, or 0 if none.
async fn sqlite_current_version(pool: &sqlx::SqlitePool) -> Result<i64> {
    let row: (i64,) = sqlx::query_as("SELECT COALESCE(MAX(version), 0) FROM schema_version")
        .fetch_one(pool)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to query schema_version: {e}")))?;
    Ok(row.0)
}

/// Run all pending SQLite migrations against the given pool.
///
/// Each migration is applied inside a transaction. On success the version is
/// recorded in `schema_version`. Migrations that have already been applied
/// (by version number) are skipped.
pub async fn run_sqlite_migrations(pool: &sqlx::SqlitePool) -> Result<()> {
    ensure_sqlite_version_table(pool).await?;
    let current = sqlite_current_version(pool).await?;
    let migrations = sqlite_migrations();

    for m in &migrations {
        if m.version <= current {
            continue;
        }
        info!(
            version = m.version,
            description = %m.description,
            "Applying SQLite migration"
        );

        let mut tx = pool.begin().await.map_err(|e| {
            LLMTraceError::Storage(format!("Failed to begin migration transaction: {e}"))
        })?;

        // Execute each statement in the migration file.
        // Split on `;` to handle multi-statement files.
        for statement in m.sql.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }
            let result = sqlx::query(stmt).execute(&mut *tx).await;
            match result {
                Ok(_) => {}
                Err(e) => {
                    // Allow ALTER TABLE ADD COLUMN to fail if column already exists
                    let upper = stmt.to_uppercase();
                    let is_alter_add =
                        upper.contains("ALTER TABLE") && upper.contains("ADD COLUMN");
                    let is_duplicate = e.to_string().contains("duplicate column");
                    if is_alter_add && is_duplicate {
                        continue;
                    }
                    return Err(LLMTraceError::Storage(format!(
                        "Migration v{} ({}) failed: {e}",
                        m.version, m.description,
                    )));
                }
            }
        }

        // Record the applied version
        sqlx::query("INSERT INTO schema_version (version, description) VALUES (?1, ?2)")
            .bind(m.version)
            .bind(&m.description)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                LLMTraceError::Storage(format!("Failed to record migration v{}: {e}", m.version))
            })?;

        tx.commit().await.map_err(|e| {
            LLMTraceError::Storage(format!("Failed to commit migration v{}: {e}", m.version))
        })?;

        info!(
            version = m.version,
            description = %m.description,
            "SQLite migration applied successfully"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PostgreSQL migration runner
// ---------------------------------------------------------------------------

#[cfg(feature = "postgres")]
/// Create the `schema_version` tracking table if it does not exist (PostgreSQL).
///
/// Handles the race condition where concurrent connections both attempt
/// `CREATE TABLE IF NOT EXISTS` at the same time — PostgreSQL can raise a
/// `unique_violation` on the internal `pg_type_typname_nsp_index` catalogue
/// constraint even with the `IF NOT EXISTS` guard.
async fn ensure_pg_version_table(pool: &sqlx::PgPool) -> Result<()> {
    let result = sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version BIGINT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            description TEXT
        )",
    )
    .execute(pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            // Concurrent CREATE TABLE can fail with a pg_type catalogue
            // duplicate or a generic "already exists" message — both are
            // harmless because the table exists by the time we continue.
            if msg.contains("pg_type_typname_nsp_index") || msg.contains("already exists") {
                Ok(())
            } else {
                Err(LLMTraceError::Storage(format!(
                    "Failed to create schema_version table: {e}"
                )))
            }
        }
    }
}

#[cfg(feature = "postgres")]
/// Return the highest applied migration version for PostgreSQL, or 0 if none.
///
/// The explicit `CAST(… AS BIGINT)` ensures the result is always `INT8`
/// regardless of whether the `version` column was created as `INTEGER`
/// (INT4) or `BIGINT` (INT8).
async fn pg_current_version(pool: &sqlx::PgPool) -> Result<i64> {
    let row: (i64,) =
        sqlx::query_as("SELECT CAST(COALESCE(MAX(version), 0) AS BIGINT) FROM schema_version")
            .fetch_one(pool)
            .await
            .map_err(|e| LLMTraceError::Storage(format!("Failed to query schema_version: {e}")))?;
    Ok(row.0)
}

#[cfg(feature = "postgres")]
/// Run all pending PostgreSQL migrations against the given pool.
///
/// Each migration is applied inside a transaction. On success the version is
/// recorded in `schema_version`. Migrations that have already been applied
/// (by version number) are skipped.
pub async fn run_pg_migrations(pool: &sqlx::PgPool) -> Result<()> {
    ensure_pg_version_table(pool).await?;
    let current = pg_current_version(pool).await?;
    let migrations = postgres_migrations();

    for m in &migrations {
        if m.version <= current {
            continue;
        }
        info!(
            version = m.version,
            description = %m.description,
            "Applying PostgreSQL migration"
        );

        let mut tx = pool.begin().await.map_err(|e| {
            LLMTraceError::Storage(format!("Failed to begin migration transaction: {e}"))
        })?;

        // Acquire a transaction-scoped advisory lock so that concurrent
        // connections serialise on migration application.  The lock is
        // automatically released when the transaction commits or rolls back.
        sqlx::query("SELECT pg_advisory_xact_lock(8675309)")
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                LLMTraceError::Storage(format!("Failed to acquire migration lock: {e}"))
            })?;

        // Re-check the current version inside the lock — another connection
        // may have already applied this migration while we were waiting.
        let inner: (i64,) =
            sqlx::query_as("SELECT CAST(COALESCE(MAX(version), 0) AS BIGINT) FROM schema_version")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    LLMTraceError::Storage(format!("Failed to re-check schema version: {e}"))
                })?;

        if m.version <= inner.0 {
            // Already applied by a concurrent runner — skip.
            tx.rollback().await.ok();
            continue;
        }

        // Execute each statement in the migration file.
        for statement in m.sql.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }
            sqlx::query(stmt).execute(&mut *tx).await.map_err(|e| {
                LLMTraceError::Storage(format!(
                    "Migration v{} ({}) failed: {e}",
                    m.version, m.description,
                ))
            })?;
        }

        // Record the applied version
        sqlx::query("INSERT INTO schema_version (version, description) VALUES ($1, $2)")
            .bind(m.version)
            .bind(&m.description)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                LLMTraceError::Storage(format!("Failed to record migration v{}: {e}", m.version))
            })?;

        tx.commit().await.map_err(|e| {
            LLMTraceError::Storage(format!("Failed to commit migration v{}: {e}", m.version))
        })?;

        info!(
            version = m.version,
            description = %m.description,
            "PostgreSQL migration applied successfully"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public pool helpers for the CLI `migrate` subcommand
// ---------------------------------------------------------------------------

/// Open a SQLite connection pool (public wrapper for the CLI).
pub async fn open_sqlite_pool(database_url: &str) -> Result<SqlitePool> {
    let connect_opts = SqliteConnectOptions::from_str(database_url)
        .map_err(|e| LLMTraceError::Storage(format!("Invalid database URL: {e}")))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);

    let max_conns: u32 = if database_url.contains(":memory:") {
        1
    } else {
        10
    };

    sqlx::pool::PoolOptions::<sqlx::Sqlite>::new()
        .max_connections(max_conns)
        .connect_with(connect_opts)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to connect to SQLite: {e}")))
}

#[cfg(feature = "postgres")]
/// Open a PostgreSQL connection pool (public wrapper for the CLI).
pub async fn open_pg_pool(database_url: &str) -> Result<sqlx::PgPool> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
        .map_err(|e| LLMTraceError::Storage(format!("Failed to connect to PostgreSQL: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_migrations_are_ordered() {
        let migrations = sqlite_migrations();
        assert!(!migrations.is_empty());
        for (i, m) in migrations.iter().enumerate() {
            assert_eq!(
                m.version,
                (i + 1) as i64,
                "Migration versions must be sequential starting from 1"
            );
        }
    }

    #[test]
    fn test_sqlite_migrations_have_content() {
        for m in sqlite_migrations() {
            assert!(
                !m.sql.trim().is_empty(),
                "Migration v{} ({}) has empty SQL",
                m.version,
                m.description,
            );
            assert!(
                !m.description.is_empty(),
                "Migration v{} has empty description",
                m.version,
            );
        }
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn test_postgres_migrations_are_ordered() {
        let migrations = postgres_migrations();
        assert!(!migrations.is_empty());
        for (i, m) in migrations.iter().enumerate() {
            assert_eq!(
                m.version,
                (i + 1) as i64,
                "Migration versions must be sequential starting from 1"
            );
        }
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn test_postgres_migrations_have_content() {
        for m in postgres_migrations() {
            assert!(
                !m.sql.trim().is_empty(),
                "Migration v{} ({}) has empty SQL",
                m.version,
                m.description,
            );
        }
    }

    #[tokio::test]
    async fn test_sqlite_migration_runner_applies_all() {
        let pool = crate::sqlite::open_pool("sqlite::memory:").await.unwrap();
        run_sqlite_migrations(&pool).await.unwrap();

        // Verify schema_version table has all migrations recorded
        let current = sqlite_current_version(&pool).await.unwrap();
        let expected = sqlite_migrations().len() as i64;
        assert_eq!(current, expected);
    }

    #[tokio::test]
    async fn test_sqlite_migration_runner_is_idempotent() {
        let pool = crate::sqlite::open_pool("sqlite::memory:").await.unwrap();

        // Run twice — second run should be a no-op
        run_sqlite_migrations(&pool).await.unwrap();
        run_sqlite_migrations(&pool).await.unwrap();

        let current = sqlite_current_version(&pool).await.unwrap();
        let expected = sqlite_migrations().len() as i64;
        assert_eq!(current, expected);
    }

    #[tokio::test]
    async fn test_sqlite_schema_version_tracking() {
        let pool = crate::sqlite::open_pool("sqlite::memory:").await.unwrap();
        run_sqlite_migrations(&pool).await.unwrap();

        // Verify each migration version is recorded with a description
        let rows: Vec<(i64, String)> =
            sqlx::query_as("SELECT version, description FROM schema_version ORDER BY version")
                .fetch_all(&pool)
                .await
                .unwrap();

        let migrations = sqlite_migrations();
        assert_eq!(rows.len(), migrations.len());
        for (row, migration) in rows.iter().zip(migrations.iter()) {
            assert_eq!(row.0, migration.version);
            assert_eq!(row.1, migration.description);
        }
    }

    #[tokio::test]
    async fn test_sqlite_tables_exist_after_migration() {
        let pool = crate::sqlite::open_pool("sqlite::memory:").await.unwrap();
        run_sqlite_migrations(&pool).await.unwrap();

        // Verify all expected tables exist
        let tables: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .fetch_all(&pool)
                .await
                .unwrap();

        let table_names: Vec<&str> = tables.iter().map(|t| t.0.as_str()).collect();
        assert!(table_names.contains(&"traces"), "traces table missing");
        assert!(table_names.contains(&"spans"), "spans table missing");
        assert!(table_names.contains(&"tenants"), "tenants table missing");
        assert!(
            table_names.contains(&"tenant_configs"),
            "tenant_configs table missing"
        );
        assert!(
            table_names.contains(&"audit_events"),
            "audit_events table missing"
        );
        assert!(table_names.contains(&"api_keys"), "api_keys table missing");
        assert!(
            table_names.contains(&"schema_version"),
            "schema_version table missing"
        );
    }

    #[tokio::test]
    async fn test_sqlite_partial_migration_resumes() {
        let pool = crate::sqlite::open_pool("sqlite::memory:").await.unwrap();

        // Manually apply only migration 1 via the runner
        ensure_sqlite_version_table(&pool).await.unwrap();
        let first = &sqlite_migrations()[0];
        for statement in first.sql.split(';') {
            let stmt = statement.trim();
            if stmt.is_empty() {
                continue;
            }
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO schema_version (version, description) VALUES (?1, ?2)")
            .bind(first.version)
            .bind(&first.description)
            .execute(&pool)
            .await
            .unwrap();

        // Now run the full migration runner — should only apply 2 and 3
        run_sqlite_migrations(&pool).await.unwrap();

        let current = sqlite_current_version(&pool).await.unwrap();
        assert_eq!(current, sqlite_migrations().len() as i64);
    }
}
