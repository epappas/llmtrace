import { NextRequest } from "next/server";
import { proxyGet, proxyMutate } from "@/lib/proxy-helpers";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

export async function GET(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = "/api/v1/" + path.join("/");
  return proxyGet(req, fullPath);
}

export async function POST(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = "/api/v1/" + path.join("/");
  return proxyMutate(req, fullPath, "POST");
}

export async function PUT(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = "/api/v1/" + path.join("/");
  return proxyMutate(req, fullPath, "PUT");
}

export async function DELETE(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = "/api/v1/" + path.join("/");
  return proxyMutate(req, fullPath, "DELETE");
}
