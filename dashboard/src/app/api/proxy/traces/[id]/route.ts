import { NextRequest, NextResponse } from "next/server";
import { proxyGet } from "@/lib/proxy-helpers";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  return proxyGet(req, `/api/v1/traces/${id}`);
}

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const clickhouseUrl = process.env.CLICKHOUSE_URL ?? "http://clickhouse:8123";
  
  try {
    console.log(`[Dashboard API] Direct delete for trace: ${id}`);
    
    // Delete from both tables
    const queries = [
      `ALTER TABLE llmtrace.spans DELETE WHERE trace_id = '${id}'`,
      `ALTER TABLE llmtrace.traces DELETE WHERE trace_id = '${id}'`,
    ];

    for (const query of queries) {
      await fetch(clickhouseUrl, {
        method: "POST",
        body: query,
      });
    }

    return new NextResponse(null, { status: 204 });
  } catch (e) {
    console.error("[Dashboard API] Trace delete failed:", e);
    return NextResponse.json({ error: "Failed to delete trace" }, { status: 500 });
  }
}
