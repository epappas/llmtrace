// ---------------------------------------------------------------------------
// LLMTrace REST API Client — typed fetch wrapper
// ---------------------------------------------------------------------------

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

/** Default tenant ID (nil UUID) used as a fallback for the "default" tenant. */
export const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000000";

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
  prompt: string;
  response: string | null;
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
  newest_trace?: string;
  oldest_trace?: string;
}

export interface Tenant {
  id: string;
  name: string;
  plan: string;
  created_at: string;
  config: Record<string, unknown>;
}

export interface ApiKey {
  id: string;
  name: string;
  key?: string; // Only present on creation
  key_prefix: string;
  role: string;
  created_at: string;
  tenant_id: string;
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
  const url = `${API_BASE}${path}`;
  console.log(`[API] Fetching: ${url}${tenantId ? ` (Tenant: ${tenantId})` : ""}`);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(tenantId ? { "X-LLMTrace-Tenant-ID": tenantId } : {}),
  };

  try {
    const res = await fetch(url, {
      ...init,
      headers: { ...headers, ...(init?.headers as Record<string, string>) },
      cache: "no-store",
    });

    console.log(`[API] Response from ${url}: ${res.status} ${res.statusText}`);

    if (!res.ok) {
      const body = await res.text();
      console.error(`[API] Error body from ${url}:`, body);
      throw new Error(`API ${res.status}: ${body}`);
    }

    if (res.status === 204) {
      return {} as T;
    }

    return res.json() as Promise<T>;
  } catch (e) {
    console.error(`[API] Fetch failed for ${url}:`, e);
    throw e;
  }
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

/** Delete a single trace by ID. */
export async function deleteTrace(
  traceId: string,
  tenantId?: string,
): Promise<void> {
  await apiFetch(`/api/v1/traces/${traceId}`, { method: "DELETE" }, tenantId);
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

/** Delete a single span by ID. */
export async function deleteSpan(
  spanId: string,
  tenantId?: string,
): Promise<void> {
  await apiFetch(`/api/v1/spans/${spanId}`, { method: "DELETE" }, tenantId);
}

/** Get storage stats. */
export async function getStats(tenantId?: string): Promise<StorageStats> {
  return apiFetch("/api/v1/stats", undefined, tenantId);
}

/** Get global storage stats across all tenants. */
export async function getGlobalStats(): Promise<StorageStats> {
  try {
    const tenants = await listTenants();
    console.log(`[API] getGlobalStats: Found ${tenants.length} tenants`);
    const statsPromises = tenants.map(t => getStats(t.id).catch(err => {
      console.warn(`[API] Failed to fetch stats for tenant ${t.id}:`, err);
      return null;
    }));
    const allStats = await Promise.all(statsPromises);
    
    const aggregated = allStats.reduce((acc: StorageStats, s) => {
      if (!s) return acc;
      return {
        ...acc,
        total_traces: acc.total_traces + s.total_traces,
        total_spans: acc.total_spans + s.total_spans,
        total_cost_usd: acc.total_cost_usd + s.total_cost_usd,
      };
    }, { total_traces: 0, total_spans: 0, total_cost_usd: 0 });

    console.log("[API] getGlobalStats result:", aggregated);
    return aggregated;
  } catch (e) {
    console.error("[API] Failed to fetch global stats:", e);
    return { total_traces: 0, total_spans: 0, total_cost_usd: 0 };
  }
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
  // Use a cache-buster to ensure we get the absolute latest state from the DB
  return apiFetch(`/api/v1/tenants?_t=${Date.now()}`);
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

/** List API keys for a tenant. */
export async function listApiKeys(tenantId: string): Promise<ApiKey[]> {
  return apiFetch("/api/v1/auth/keys", undefined, tenantId);
}

/** Create a new API key for a tenant. */
export async function createApiKey(
  tenantId: string,
  name: string,
  role: "admin" | "operator" | "viewer" = "operator",
): Promise<ApiKey> {
  return apiFetch("/api/v1/auth/keys", {
    method: "POST",
    body: JSON.stringify({ tenant_id: tenantId, name, role }),
  }, tenantId);
}

/** Health check. */
export async function healthCheck(): Promise<{ status: string }> {
  return apiFetch("/health");
}

/** Helper: Find the tenant with the most recent activity. */
export async function findActiveTenant(): Promise<string | undefined> {
  try {
    const tenants = await listTenants();
    console.log(`[API] findActiveTenant: Found ${tenants.length} tenants`);
    
    if (tenants.length === 0) {
      console.warn("[API] No tenants found in the database.");
      setStoredTenant(undefined);
      return undefined;
    }

    // Check localStorage first and verify it still exists
    if (typeof window !== "undefined") {
      const stored = localStorage.getItem("llmtrace_tenant_id");
      if (stored && tenants.some(t => t.id === stored)) {
        console.log(`[API] Using stored tenant ID: ${stored}`);
        return stored;
      }
    }

    // Fetch stats for all tenants in parallel to find the one with the most activity
    const statsPromises = tenants.map(t => 
      getStats(t.id).then(s => ({ 
        id: t.id, 
        count: s.total_traces, 
        newest: s.newest_trace ? new Date(s.newest_trace).getTime() : 0 
      })).catch(err => {
        console.warn(`[API] Error fetching stats for tenant ${t.id}:`, err);
        return { id: t.id, count: 0, newest: 0 };
      })
    );
    
    const results = await Promise.all(statsPromises);
    // Sort by newest trace first, then by count
    results.sort((a, b) => b.newest - a.newest || b.count - a.count);
    
    const activeId = results[0]?.id || DEFAULT_TENANT_ID;
    console.log(`[API] Identified most active tenant: ${activeId}`);

    // Only set stored tenant if none is currently selected
    if (activeId && typeof window !== "undefined" && !localStorage.getItem("llmtrace_tenant_id")) {
      setStoredTenant(activeId);
    }
    return activeId;
  } catch (e) {
    console.error("[API] findActiveTenant failed:", e);
    return DEFAULT_TENANT_ID;
  }
}

/** Helper: Store the selected tenant ID in localStorage. */
export function setStoredTenant(tenantId: string | undefined): void {
  if (typeof window === "undefined") return;
  if (tenantId) {
    localStorage.setItem("llmtrace_tenant_id", tenantId);
  } else {
    localStorage.removeItem("llmtrace_tenant_id");
  }
}
