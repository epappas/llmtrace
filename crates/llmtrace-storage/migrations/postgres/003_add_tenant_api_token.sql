-- 003_add_tenant_api_token.sql: Add api_token to tenants table

-- IMPORTANT:
-- We cannot add `api_token` as `NOT NULL DEFAULT '' UNIQUE` in one step because
-- existing rows would all get the same default value (''), and the UNIQUE
-- constraint / index creation would fail.
--
-- Strategy:
-- 1. Add column as nullable (no default).
-- 2. Backfill unique tokens for any existing rows (including previously-empty).
--    The token is derived from the tenant UUID to guarantee uniqueness.
-- 3. Enforce NOT NULL.
-- 4. Add a unique index.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS api_token VARCHAR(255);

UPDATE tenants
SET api_token = 'llmt_' || md5(id::text || clock_timestamp()::text)
WHERE api_token IS NULL OR api_token = '';

ALTER TABLE tenants
    ALTER COLUMN api_token SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS tenants_api_token_key ON tenants(api_token);
