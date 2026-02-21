import { NextRequest, NextResponse } from "next/server";

const backendUrlCandidates = [
  process.env.LLMTRACE_PROXY_URL,
  process.env.LLMTRACE_BACKEND_URL,
  "http://llmtrace-proxy:8080",
  "http://llmtrace-proxy:8081",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:8081",
  "http://localhost:8080",
  "http://localhost:8081",
].filter((value, index, arr): value is string => Boolean(value) && arr.indexOf(value) === index);

async function fetchWithFallback(
  backendPath: string,
  init: RequestInit,
): Promise<{ response: Response; backendUrl: string }> {
  let lastError: unknown;
  let lastResponse: Response | undefined;
  const normalizedPath = backendPath.split("?")[0] ?? backendPath;
  const retryOnNotFoundPaths = [
    "/api/v1/config/live",
    "/config/live",
    "/swagger-ui",
    "/swagger-ui/",
    "/api-doc/openapi.json",
  ];
  const shouldRetryOnNotFound = retryOnNotFoundPaths.some((path) =>
    normalizedPath.startsWith(path),
  );

  for (const backendUrl of backendUrlCandidates) {
    const url = new URL(backendPath, backendUrl);
    try {
      const response = await fetch(url.toString(), init);
      if (shouldRetryOnNotFound && response.status === 404) {
        lastResponse = response;
        continue;
      }
      return { response, backendUrl };
    } catch (error) {
      lastError = error;
    }
  }

  if (lastResponse) {
    return {
      response: lastResponse,
      backendUrl: "none",
    };
  }

  throw lastError ?? new Error("No backend URL candidates configured");
}

/**
 * Proxy a GET request to the LLMTrace backend, forwarding query params
 * and relevant headers (tenant identification).
 */
export async function proxyGet(
  req: NextRequest,
  backendPath: string,
): Promise<NextResponse> {
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
