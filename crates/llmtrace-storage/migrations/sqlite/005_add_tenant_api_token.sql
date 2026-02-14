-- 005_add_tenant_api_token.sql: Add api_token to tenants table

-- Step 1: Add the column allowing NULLs initially
ALTER TABLE tenants ADD COLUMN api_token TEXT;

-- Step 2: Populate existing rows with a random token if needed, 
-- or we can just leave them NULL and handle it in the app.
-- For simplicity, we'll make it NOT NULL but with a default for new rows
-- Actually, SQLite ALTER TABLE doesn't support NOT NULL without a DEFAULT.
-- We will use a placeholder or just leave it nullable for now and enforce in app.
-- To make it UNIQUE, we add an index.

CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_api_token ON tenants(api_token);
