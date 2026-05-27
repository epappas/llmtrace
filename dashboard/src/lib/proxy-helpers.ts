import { NextRequest, NextResponse } from "next/server";
import { fetchWithFallback } from "./backend";
import { isAuthDisabled } from "./auth";
import { isUpstreamPublic } from "./public-paths";

// Allow-list prefixes for upstream response headers that the browser
// needs to see. The proxy emits `x-llmtrace-*` for every traced response
// (trace-id, action, score, policy-mode, findings, etc.) plus
// `x-request-id` for cross-system correlation. A prefix match means new
// `x-llmtrace-*` headers added on the proxy side flow through without
// further dashboard changes — see incident on 2026-05-27 where #297's
// new x-llmtrace-action / x-llmtrace-score / x-llmtrace-policy-mode
// headers were silently stripped by an earlier hardcoded name list.
const FORWARDED_RESPONSE_HEADER_PREFIXES: readonly string[] = ["x-llmtrace-"];
const FORWARDED_RESPONSE_HEADER_NAMES: readonly string[] = ["x-request-id"];

function buildHeaders(
  req: NextRequest,
  backendPath: string,
  extra: Record<string, string> = {},
): Record<string, string> | NextResponse {
  const headers: Record<string, string> = { ...extra };

  // Tenant header resolution: prefer an explicit incoming header (used by
  // dashboard pages that drive a tenant picker, e.g. /traces). Fall back to
  // the deployment-pinned tenant set at provisioning time so that
  // dashboard-originated traffic (e.g. /playground chat completions) is
  // attributed to the real provisioned tenant instead of spawning a
  // throwaway tenant per call on the proxy.
  const tenantHeader =
    req.headers.get("x-llmtrace-tenant-id") ??
    process.env.LLMTRACE_DASHBOARD_TENANT_ID ??
    null;
  if (tenantHeader) headers["X-LLMTrace-Tenant-ID"] = tenantHeader;

  const authHeader = req.headers.get("authorization");
  if (authHeader) {
    headers["Authorization"] = authHeader;
    return headers;
  }

  // Genuinely-public upstream paths: skip the dashboard auth gate so the
  // proxy can serve them on its own allow-list. The middleware also
  // declares these public, so an iframe / scraper can fetch them
  // without first signing into the dashboard.
  if (isUpstreamPublic(backendPath)) {
    return headers;
  }

  // Local-dev escape hatch: when auth is disabled the dashboard mirrors the
  // pre-#250 behaviour — inject the bootstrap admin key if one is configured,
  // otherwise pass the request through unauthenticated (the local dev proxy
  // also runs without an admin key, so no Authorization header is needed).
  if (isAuthDisabled()) {
    if (process.env.LLMTRACE_AUTH_ADMIN_KEY) {
      headers["Authorization"] = `Bearer ${process.env.LLMTRACE_AUTH_ADMIN_KEY}`;
    }
    return headers;
  }

  return NextResponse.json(
    { error: { message: "auth required", type: "auth_required" } },
    { status: 401 },
  );
}

function buildResponseHeaders(res: Response): Record<string, string> {
  const out: Record<string, string> = {
    "Content-Type": res.headers.get("Content-Type") ?? "application/json",
  };
  res.headers.forEach((value, name) => {
    const lower = name.toLowerCase();
    if (FORWARDED_RESPONSE_HEADER_NAMES.includes(lower)) {
      out[lower] = value;
      return;
    }
    for (const prefix of FORWARDED_RESPONSE_HEADER_PREFIXES) {
      if (lower.startsWith(prefix)) {
        out[lower] = value;
        return;
      }
    }
  });
  return out;
}

/**
 * Proxy a GET request to the LLMTrace backend, forwarding query params
 * and relevant headers (tenant identification, Authorization).
 */
export async function proxyGet(
  req: NextRequest,
  backendPath: string,
): Promise<NextResponse> {
  const headers = buildHeaders(req, backendPath);
  if (headers instanceof NextResponse) return headers;

  try {
    const pathWithQuery = `${backendPath}${req.nextUrl.search}`;
    const { response: res, backendUrl } = await fetchWithFallback(pathWithQuery, {
      headers,
      cache: "no-store",
    });
    console.log(`[Proxy] GET ${pathWithQuery} via ${backendUrl}`);
    const body = await res.text();
    return new NextResponse(body, {
      status: res.status,
      headers: buildResponseHeaders(res),
    });
  } catch (e) {
    console.error("Proxy error:", e);
    return NextResponse.json(
      { error: { message: "Backend unavailable", type: "proxy_error" } },
      { status: 502 },
    );
  }
}

/**
 * Proxy a mutating request (POST/PUT/DELETE) to the LLMTrace backend.
 */
export async function proxyMutate(
  req: NextRequest,
  backendPath: string,
  method: string,
): Promise<NextResponse> {
  const headers = buildHeaders(req, backendPath, { "Content-Type": "application/json" });
  if (headers instanceof NextResponse) return headers;

  let bodyText: string | undefined;
  if (method !== "DELETE") {
    bodyText = await req.text();
  }

  try {
    const { response: res, backendUrl } = await fetchWithFallback(backendPath, {
      method,
      headers,
      body: bodyText,
    });
    console.log(`[Proxy] ${method} ${backendPath} via ${backendUrl}`);
    const body = await res.text();
    return new NextResponse(body, {
      status: res.status,
      headers: buildResponseHeaders(res),
    });
  } catch (e) {
    console.error("Proxy error:", e);
    return NextResponse.json(
      { error: { message: "Backend unavailable", type: "proxy_error" } },
      { status: 502 },
    );
  }
}
