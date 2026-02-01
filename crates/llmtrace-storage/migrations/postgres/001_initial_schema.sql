-- 001_initial_schema.sql: tenants, tenant_configs, audit_events, api_keys for PostgreSQL

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    config JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tenant_configs (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    security_thresholds JSONB NOT NULL DEFAULT '{}',
    feature_flags JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    event_type VARCHAR(100) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    data JSONB NOT NULL DEFAULT '{}',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_events(tenant_id, event_type);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    key_prefix VARCHAR(16) NOT NULL,
    role VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
