-- 005_add_tenant_api_token.sql: Add api_token to tenants table

-- IMPORTANT:
-- We cannot add `api_token` as `NOT NULL DEFAULT '' UNIQUE` because existing
-- rows would all get the same default value (''), causing UNIQUE violations.
--
-- Strategy:
-- 1. Add the column as nullable.
-- 2. Backfill unique tokens for existing rows.
-- 3. Rebuild the `tenants` table to enforce `NOT NULL` on `api_token`.

ALTER TABLE tenants ADD COLUMN api_token TEXT;

UPDATE tenants
SET api_token = 'llmt_' || lower(hex(randomblob(32)))
WHERE api_token IS NULL OR api_token = '';

DROP TABLE IF EXISTS tenants_new;
CREATE TABLE tenants_new (
    id TEXT NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    plan TEXT NOT NULL,
    created_at TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    api_token TEXT NOT NULL
);

INSERT INTO tenants_new (id, name, plan, created_at, config, api_token)
SELECT id, name, plan, created_at, config, api_token
FROM tenants;

DROP TABLE tenants;
ALTER TABLE tenants_new RENAME TO tenants;

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_api_token ON tenants(api_token);
