-- 005_add_tenant_api_token.sql: Add api_token to tenants table

-- Step 1: Add the column with a default value to satisfy NOT NULL for existing rows
ALTER TABLE tenants ADD COLUMN api_token TEXT NOT NULL DEFAULT '';

-- Step 2: To make it UNIQUE, we add an index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_api_token ON tenants(api_token);
