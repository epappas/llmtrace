import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = "http://llmtrace-proxy:8080";

/**
 * Proxy a GET request to the LLMTrace backend, forwarding query params
 * and relevant headers (tenant identification).
 */
export async function proxyGet(
  req: NextRequest,
  backendPath: string,
): Promise<NextResponse> {
  console.log(`[Proxy] GET request to ${backendPath}. BACKEND_URL is ${BACKEND_URL}`);
  const url = new URL(backendPath, BACKEND_URL);
  // Forward query params
  req.nextUrl.searchParams.forEach((v, k) => url.searchParams.set(k, v));
  
  console.log(`[Proxy] Fetching from upstream: ${url.toString()}`);

  const headers: Record<string, string> = {};
  const tenantHeader = req.headers.get("x-llmtrace-tenant-id");
  if (tenantHeader) headers["X-LLMTrace-Tenant-ID"] = tenantHeader;
  
  // Forward incoming auth, or inject bootstrap admin key
  const authHeader = req.headers.get("authorization");
  if (authHeader) {
    headers["Authorization"] = authHeader;
  } else if (process.env.LLMTRACE_AUTH_ADMIN_KEY) {
    headers["Authorization"] = `Bearer ${process.env.LLMTRACE_AUTH_ADMIN_KEY}`;
  }

  try {
    const res = await fetch(url.toString(), { headers, cache: "no-store" });
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
  const url = new URL(backendPath, BACKEND_URL);

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  const tenantHeader = req.headers.get("x-llmtrace-tenant-id");
  if (tenantHeader) headers["X-LLMTrace-Tenant-ID"] = tenantHeader;

  // Forward incoming auth, or inject bootstrap admin key
  const authHeader = req.headers.get("authorization");
  if (authHeader) {
    headers["Authorization"] = authHeader;
  } else if (process.env.LLMTRACE_AUTH_ADMIN_KEY) {
    headers["Authorization"] = `Bearer ${process.env.LLMTRACE_AUTH_ADMIN_KEY}`;
  }

  let bodyText: string | undefined;
  if (method !== "DELETE") {
    bodyText = await req.text();
  }

  try {
    const res = await fetch(url.toString(), {
      method,
      headers,
      body: bodyText,
    });
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
