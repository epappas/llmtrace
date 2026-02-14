-- 006_add_monitoring_scope.sql: add monitoring_scope, rate_limit_rpm, monthly_budget to tenant_configs

ALTER TABLE tenant_configs ADD COLUMN monitoring_scope TEXT NOT NULL DEFAULT 'hybrid';
ALTER TABLE tenant_configs ADD COLUMN rate_limit_rpm INTEGER;
ALTER TABLE tenant_configs ADD COLUMN monthly_budget REAL;
