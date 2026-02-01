-- 001_initial_schema.sql: traces and spans tables for SQLite

CREATE TABLE IF NOT EXISTS traces (
    trace_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, trace_id)
);

CREATE INDEX IF NOT EXISTS idx_traces_created ON traces(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS spans (
    span_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    parent_span_id TEXT,
    tenant_id TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    provider TEXT NOT NULL,
    model_name TEXT NOT NULL,
    prompt TEXT NOT NULL,
    response TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    time_to_first_token_ms INTEGER,
    duration_ms INTEGER,
    status_code INTEGER,
    error_message TEXT,
    estimated_cost_usd REAL,
    security_score INTEGER,
    security_findings TEXT NOT NULL DEFAULT '[]',
    tags TEXT NOT NULL DEFAULT '{}',
    events TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (tenant_id, span_id)
);

CREATE INDEX IF NOT EXISTS idx_spans_trace ON spans(tenant_id, trace_id);
CREATE INDEX IF NOT EXISTS idx_spans_time ON spans(tenant_id, start_time);
CREATE INDEX IF NOT EXISTS idx_spans_provider ON spans(tenant_id, provider);
CREATE INDEX IF NOT EXISTS idx_spans_model ON spans(tenant_id, model_name);
CREATE INDEX IF NOT EXISTS idx_spans_security ON spans(tenant_id, security_score);
CREATE INDEX IF NOT EXISTS idx_spans_operation ON spans(tenant_id, operation_name);
