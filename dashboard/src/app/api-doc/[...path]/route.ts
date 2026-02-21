import { NextRequest } from "next/server";
import { proxyGet } from "@/lib/proxy-helpers";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

export async function GET(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = "/api-doc/" + path.join("/");
  return proxyGet(req, fullPath);
}
