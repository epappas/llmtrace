import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy-helpers";

export async function GET(req: NextRequest) {
  return proxyGet(req, "/health");
}
