import { NextRequest } from "next/server";
import { proxyGet, proxyMutate } from "@/lib/proxy-helpers";

export async function GET(req: NextRequest) {
  return proxyGet(req, "/api/v1/tenants");
}

export async function POST(req: NextRequest) {
  return proxyMutate(req, "/api/v1/tenants", "POST");
}
