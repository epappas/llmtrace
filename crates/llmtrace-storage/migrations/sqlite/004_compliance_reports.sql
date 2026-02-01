-- Migration 004: compliance_reports table for persistent report storage
CREATE TABLE IF NOT EXISTS compliance_reports (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    report_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    content TEXT,
    error TEXT
);

CREATE INDEX IF NOT EXISTS idx_reports_tenant ON compliance_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_created ON compliance_reports(tenant_id, created_at DESC)
