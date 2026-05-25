import { NextRequest, NextResponse } from "next/server";
import { fetchWithFallback } from "@/lib/backend";

// `/health` MUST stay unauthenticated — Basilica's k8s readiness probe hits
// it before any session cookie exists, and the upstream proxy itself accepts
// `/health` without auth. We therefore bypass the dashboard auth gate here.
export async function GET(_req: NextRequest): Promise<NextResponse> {
  try {
    const { response } = await fetchWithFallback("/health", {
      method: "GET",
      cache: "no-store",
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") ?? "application/json",
      },
    });
  } catch (e) {
    console.error("[health] proxy error:", e);
    return NextResponse.json(
      { error: { message: "Backend unavailable", type: "proxy_error" } },
      { status: 502 },
    );
  }
}
