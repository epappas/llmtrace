-- 002_metadata_tables.sql: tenants, tenant_configs, audit_events, api_keys

CREATE TABLE IF NOT EXISTS tenants (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL,
    created_at TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tenant_configs (
    tenant_id TEXT NOT NULL PRIMARY KEY,
    security_thresholds TEXT NOT NULL DEFAULT '{}',
    feature_flags TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT NOT NULL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource TEXT NOT NULL,
    data TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_events(tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(tenant_id, event_type);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT NOT NULL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
