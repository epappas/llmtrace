-- LLM-as-a-Judge verdicts (issue #43). Populated by the async judge
-- worker and consumed by the Pipeline Learning service (issue #44)
-- as supervised training labels.
CREATE TABLE IF NOT EXISTS judge_verdicts (
    id UUID PRIMARY KEY,
    trace_id UUID NOT NULL,
    tenant_id UUID NOT NULL,
    is_threat BOOLEAN NOT NULL,
    category TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    security_score SMALLINT NOT NULL,
    recommended_action TEXT NOT NULL,
    reasoning TEXT NOT NULL,
    mode TEXT NOT NULL,
    model_used TEXT NOT NULL,
    latency_ms BIGINT NOT NULL,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_judge_verdicts_trace
    ON judge_verdicts (trace_id);

CREATE INDEX IF NOT EXISTS idx_judge_verdicts_tenant_time
    ON judge_verdicts (tenant_id, created_at DESC);
