/**
 * Single source of truth for paths the upstream LLMTrace proxy serves
 * WITHOUT auth (matches the proxy's own auth-middleware allow-list).
 * Both `middleware.ts` and `proxy-helpers.ts` consult this list so the
 * two layers cannot diverge — historically they did, see issue #276.
 */
export const UPSTREAM_PUBLIC_PATHS: readonly string[] = [
  "/api-doc",
  "/swagger-ui",
  "/health",
];

/**
 * Return true when `backendPath` is in the upstream proxy's no-auth
 * allow-list. Used by proxy-helpers to skip the dashboard-side auth
 * requirement for paths the proxy serves openly.
 */
export function isUpstreamPublic(backendPath: string): boolean {
  // Strip query string and any trailing slash before matching.
  const path = backendPath.split("?")[0].replace(/\/+$/, "");
  return UPSTREAM_PUBLIC_PATHS.some((p) => path === p || path.startsWith(`${p}/`));
}
