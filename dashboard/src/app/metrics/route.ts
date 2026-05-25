import { NextRequest, NextResponse } from "next/server";
import { fetchWithFallback } from "@/lib/backend";

// `/metrics` is exposed unauthenticated by design so scrapers (Prometheus,
// k8s discovery) can pull it without holding a dashboard session. The
// upstream proxy enforces network-level ACLs on its metrics port.
export async function GET(_req: NextRequest): Promise<NextResponse> {
  try {
    const { response } = await fetchWithFallback("/metrics", {
      method: "GET",
      cache: "no-store",
    });
    const body = await response.text();
    return new NextResponse(body, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") ?? "text/plain",
      },
    });
  } catch (e) {
    console.error("[metrics] proxy error:", e);
    return NextResponse.json(
      { error: { message: "Backend unavailable", type: "proxy_error" } },
      { status: 502 },
    );
  }
}
