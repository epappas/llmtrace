// ---------------------------------------------------------------------------
// Shared TypeScript types that mirror Rust API payloads.
// ---------------------------------------------------------------------------

/**
 * An audit log entry recorded by the proxy for tenant-scoped actions
 * (tenant CRUD, API key mint/revoke, config changes, etc.).
 *
 * Mirrors `llmtrace_core::AuditEvent`.
 */
export interface AuditEvent {
  id: string;
  tenant_id: string;
  event_type: string;
  actor: string;
  resource: string;
  data: unknown;
  timestamp: string; // ISO 8601
}
