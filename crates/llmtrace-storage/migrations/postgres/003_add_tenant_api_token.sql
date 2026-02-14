-- 003_add_tenant_api_token.sql: Add api_token to tenants table

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS api_token VARCHAR(255) UNIQUE;

-- We could generate random tokens for existing tenants here, but we'll handle it via code logic 
-- if they are missing, or they can reset them.
