-- 004_add_monitoring_scope.sql: add monitoring_scope, rate_limit_rpm, monthly_budget to tenant_configs

ALTER TABLE tenant_configs 
ADD COLUMN monitoring_scope VARCHAR(20) NOT NULL DEFAULT 'hybrid',
ADD COLUMN rate_limit_rpm INTEGER,
ADD COLUMN monthly_budget DOUBLE PRECISION;
