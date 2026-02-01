// ---------------------------------------------------------------------------
// LLMTrace REST API Client — typed fetch wrapper
// ---------------------------------------------------------------------------

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

// ---------------------------------------------------------------------------
// Core types (mirror Rust API responses)
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface TraceEvent {
  trace_id: string;
  tenant_id: string;
  spans: TraceSpan[];
  created_at: string;
}

export interface TraceSpan {
  span_id: string;
  trace_id: string;
  tenant_id: string;
  operation_name: string;
  provider: string;
  model_name: string;
  prompt_text: string;
  response_text: string | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  latency_ms: number | null;
  ttft_ms: number | null;
  security_score: number;
  security_findings: SecurityFinding[];
  agent_actions: AgentAction[];
  estimated_cost_usd: number | null;
  tags: Record<string, string>;
  started_at: string;
  ended_at: string | null;
}

export interface SecurityFinding {
  id: string;
  severity: string;
  finding_type: string;
  description: string;
  confidence: number;
  detected_at: string;
}

export interface AgentAction {
  id: string;
  action_type: string;
  name: string;
  arguments: string | null;
  result: string | null;
  duration_ms: number | null;
  success: boolean;
  exit_code: number | null;
  http_method: string | null;
  http_status: number | null;
  file_operation: string | null;
  metadata: Record<string, string>;
  timestamp: string;
}

export interface StorageStats {
  total_traces: number;
  total_spans: number;
  total_cost_usd: number;
}

export interface Tenant {
  id: string;
  name: string;
  plan: string;
  created_at: string;
  config: Record<string, unknown>;
}

export interface SpendSnapshot {
  tenant_id: string;
  agent_id: string;
  windows: WindowSpend[];
}

export interface WindowSpend {
  window: string;
  current_spend_usd: number;
  hard_limit_usd: number;
  soft_limit_usd: number | null;
  utilization_pct: number;
  resets_in_secs: number;
}

export interface ActionsSummary {
  total_spans: number;
  spans_with_tool_calls: number;
  spans_with_web_access: number;
  spans_with_commands: number;
  action_counts: Record<string, number>;
  top_actions: ActionFrequency[];
}

export interface ActionFrequency {
  name: string;
  action_type: string;
  count: number;
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

export interface ListTracesParams {
  start_time?: string;
  end_time?: string;
  provider?: string;
  model?: string;
  limit?: number;
  offset?: number;
}

export interface ListSpansParams {
  security_score_min?: number;
  security_score_max?: number;
  operation_name?: string;
  model?: string;
  limit?: number;
  offset?: number;
}

// ---------------------------------------------------------------------------
// Fetch helper
// ---------------------------------------------------------------------------

async function apiFetch<T>(
  path: string,
  init?: RequestInit,
  tenantId?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(tenantId ? { "X-LLMTrace-Tenant-ID": tenantId } : {}),
  };

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...headers, ...(init?.headers as Record<string, string>) },
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
  }

  return res.json() as Promise<T>;
}

function qs(params: Record<string, string | number | undefined>): string {
  const entries = Object.entries(params).filter(
    ([, v]) => v !== undefined && v !== "",
  );
  if (entries.length === 0) return "";
  return "?" + entries.map(([k, v]) => `${k}=${encodeURIComponent(v!)}`).join("&");
}

// ---------------------------------------------------------------------------
// API functions
// ---------------------------------------------------------------------------

/** List traces with optional filters. */
export async function listTraces(
  params: ListTracesParams = {},
  tenantId?: string,
): Promise<PaginatedResponse<TraceEvent>> {
  return apiFetch(`/api/v1/traces${qs(params as Record<string, string | number | undefined>)}`, undefined, tenantId);
}

/** Get a single trace by ID. */
export async function getTrace(
  traceId: string,
  tenantId?: string,
): Promise<TraceEvent> {
  return apiFetch(`/api/v1/traces/${traceId}`, undefined, tenantId);
}

/** List spans with optional filters. */
export async function listSpans(
  params: ListSpansParams = {},
  tenantId?: string,
): Promise<PaginatedResponse<TraceSpan>> {
  return apiFetch(`/api/v1/spans${qs(params as Record<string, string | number | undefined>)}`, undefined, tenantId);
}

/** Get a single span by ID. */
export async function getSpan(
  spanId: string,
  tenantId?: string,
): Promise<TraceSpan> {
  return apiFetch(`/api/v1/spans/${spanId}`, undefined, tenantId);
}

/** Get storage stats. */
export async function getStats(tenantId?: string): Promise<StorageStats> {
  return apiFetch("/api/v1/stats", undefined, tenantId);
}

/** Get security findings (spans with security_score > 0). */
export async function listSecurityFindings(
  params: { limit?: number; offset?: number } = {},
  tenantId?: string,
): Promise<PaginatedResponse<TraceSpan>> {
  return apiFetch(`/api/v1/security/findings${qs(params as Record<string, string | number | undefined>)}`, undefined, tenantId);
}

/** Get current cost spend. */
export async function getCurrentCosts(
  agentId?: string,
  tenantId?: string,
): Promise<SpendSnapshot> {
  const q = agentId ? `?agent_id=${encodeURIComponent(agentId)}` : "";
  return apiFetch(`/api/v1/costs/current${q}`, undefined, tenantId);
}

/** Get agent actions summary. */
export async function getActionsSummary(
  tenantId?: string,
): Promise<ActionsSummary> {
  return apiFetch("/api/v1/actions/summary", undefined, tenantId);
}

// -- Tenant management -----------------------------------------------------

/** List all tenants. */
export async function listTenants(): Promise<Tenant[]> {
  return apiFetch("/api/v1/tenants");
}

/** Get a single tenant. */
export async function getTenant(id: string): Promise<Tenant> {
  return apiFetch(`/api/v1/tenants/${id}`);
}

/** Create a new tenant. */
export async function createTenant(
  body: { name: string; plan?: string; config?: Record<string, unknown> },
): Promise<Tenant> {
  return apiFetch("/api/v1/tenants", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** Update tenant. */
export async function updateTenant(
  id: string,
  body: { name?: string; plan?: string; config?: Record<string, unknown> },
): Promise<Tenant> {
  return apiFetch(`/api/v1/tenants/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
}

/** Delete a tenant. */
export async function deleteTenant(id: string): Promise<void> {
  await apiFetch(`/api/v1/tenants/${id}`, { method: "DELETE" });
}

/** Health check. */
export async function healthCheck(): Promise<{ status: string }> {
  return apiFetch("/health");
}
