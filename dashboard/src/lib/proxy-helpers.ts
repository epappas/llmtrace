import { NextRequest, NextResponse } from "next/server";
import { fetchWithFallback } from "./backend";
import { isAuthDisabled } from "./auth";

function buildHeaders(req: NextRequest, extra: Record<string, string> = {}): Record<string, string> | NextResponse {
  const headers: Record<string, string> = { ...extra };
  const tenantHeader = req.headers.get("x-llmtrace-tenant-id");
  if (tenantHeader) headers["X-LLMTrace-Tenant-ID"] = tenantHeader;

  const authHeader = req.headers.get("authorization");
  if (authHeader) {
    headers["Authorization"] = authHeader;
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

/**
 * Proxy a GET request to the LLMTrace backend, forwarding query params
 * and relevant headers (tenant identification, Authorization).
 */
export async function proxyGet(
  req: NextRequest,
  backendPath: string,
): Promise<NextResponse> {
  const headers = buildHeaders(req);
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
      headers: { "Content-Type": res.headers.get("Content-Type") ?? "application/json" },
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
  const headers = buildHeaders(req, { "Content-Type": "application/json" });
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
      headers: { "Content-Type": res.headers.get("Content-Type") ?? "application/json" },
    });
  } catch (e) {
    console.error("Proxy error:", e);
    return NextResponse.json(
      { error: { message: "Backend unavailable", type: "proxy_error" } },
      { status: 502 },
    );
  }
}
