-- 005_compliance_reports.sql: compliance_reports table for persistent report storage

CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    content JSONB,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant ON compliance_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_created ON compliance_reports(tenant_id, created_at DESC);
