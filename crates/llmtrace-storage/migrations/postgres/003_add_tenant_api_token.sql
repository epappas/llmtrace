-- 003_add_tenant_api_token.sql: Add api_token to tenants table

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS api_token VARCHAR(255) NOT NULL DEFAULT '' UNIQUE;
