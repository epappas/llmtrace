import { NextResponse } from "next/server";

/**
 * Returns runtime metadata about the dashboard's environment for client
 * components that need a server-side env value (e.g. the proxy URL banner
 * on `/tenants`). Authenticated by the standard middleware; only callable
 * once the operator has signed in.
 *
 * Keep this endpoint additive: client components fetch it on mount and
 * fall back gracefully when fields are missing. Never return secrets.
 */
export function GET(): NextResponse {
  return NextResponse.json({
    proxy_url: process.env.LLMTRACE_PROXY_URL ?? null,
  });
}
