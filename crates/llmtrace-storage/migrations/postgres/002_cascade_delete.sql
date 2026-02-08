-- 002_cascade_delete.sql: Add ON DELETE CASCADE to foreign keys

-- Drop existing constraints
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_tenant_id_fkey;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_tenant_id_fkey;
ALTER TABLE tenant_configs DROP CONSTRAINT IF EXISTS tenant_configs_tenant_id_fkey;

-- Re-add constraints with ON DELETE CASCADE
ALTER TABLE api_keys 
    ADD CONSTRAINT api_keys_tenant_id_fkey 
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE audit_events 
    ADD CONSTRAINT audit_events_tenant_id_fkey 
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE tenant_configs 
    ADD CONSTRAINT tenant_configs_tenant_id_fkey 
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
