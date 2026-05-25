// ---------------------------------------------------------------------------
// Dashboard session-auth helpers
// ---------------------------------------------------------------------------
//
// The dashboard requires the operator to sign in with the proxy's admin key.
// On success we set an HttpOnly cookie holding the key; subsequent requests
// pass through `middleware.ts` which injects an `Authorization: Bearer ...`
// header so the existing proxy helpers transparently authenticate upstream.
//
// The cookie name is host-scoped so multiple tenants on different Basilica
// hostnames cannot collide. See issue #250 for the full spec.

const SESSION_COOKIE_BASE = "llmtrace_session";
const HOST_SANITIZER = /[^A-Za-z0-9_-]/g;

/** Returns true when the local-dev escape hatch is enabled. */
export function isAuthDisabled(): boolean {
  return process.env.LLMTRACE_DASHBOARD_AUTH_DISABLED === "1";
}

/**
 * Host-scoped session cookie name. Two tenants on different Basilica URLs
 * therefore never share the same cookie.
 *
 * Example: `tenant-a.basilica.ai` -> `llmtrace_session__tenant-a_basilica_ai`.
 */
export function sessionCookieName(host: string | null | undefined): string {
  const safeHost = (host ?? "")
    .toLowerCase()
    .replace(/:\d+$/, "")
    .replace(HOST_SANITIZER, "_");
  if (safeHost.length === 0) return SESSION_COOKIE_BASE;
  return `${SESSION_COOKIE_BASE}__${safeHost}`;
}

/** Session cookie lifetime in seconds (24h). */
export const SESSION_TTL_SECONDS = 24 * 60 * 60;

const DEFAULT_ADMIN_USERNAME = "admin";

/**
 * Expected admin username for this dashboard, seeded at provision time via
 * `LLMTRACE_DASHBOARD_ADMIN_USERNAME` (set by
 * `deployments/basilica/lifecycle.py::_apply_dashboard_admin_username`).
 * Defaults to "admin" when unset so local dev needs no extra setup.
 */
export function expectedAdminUsername(): string {
  const raw = process.env.LLMTRACE_DASHBOARD_ADMIN_USERNAME;
  if (typeof raw !== "string") return DEFAULT_ADMIN_USERNAME;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : DEFAULT_ADMIN_USERNAME;
}

/**
 * Constant-time-ish username comparison (case-insensitive). Used by the
 * login route so per-character early-exit timing cannot leak which prefix
 * matched.
 */
export function usernameMatches(submitted: string, expected: string): boolean {
  const a = submitted.trim().toLowerCase();
  const b = expected.trim().toLowerCase();
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
