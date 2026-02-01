import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy-helpers";

export async function GET(
  req: NextRequest,
  { params }: { params: { id: string } },
) {
  return proxyGet(req, `/api/v1/traces/${params.id}`);
}
