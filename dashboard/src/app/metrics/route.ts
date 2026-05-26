import { NextRequest, NextResponse } from "next/server";
import { proxyGet } from "@/lib/proxy-helpers";

// `/metrics` is authenticated by design (issue #280, R10): the upstream
// proxy's auth middleware does NOT allow-list this path, so the dashboard
// must forward the operator's session as a bearer. We route through
// `proxyGet` so the middleware-injected `Authorization` header (or the
// auth-disabled escape hatch) reaches the proxy. The previous direct
// `fetchWithFallback` call sent the request unauthenticated and the
// proxy correctly returned 401 — see #280 for the regression history.
export async function GET(req: NextRequest): Promise<NextResponse> {
  return proxyGet(req, "/metrics");
}
