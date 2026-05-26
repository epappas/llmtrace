import { NextRequest } from "next/server";
import { proxyGet, proxyMutate } from "@/lib/proxy-helpers";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

function mapProxyPath(path: string[]): string {
  if (path.length === 0) return "/";
  const first = path[0];
  const swaggerAssetFiles = new Set([
    "swagger-ui.css",
    "swagger-ui-bundle.js",
    "swagger-ui-standalone-preset.js",
    "swagger-initializer.js",
    "index.css",
    "oauth2-redirect.html",
    "favicon-16x16.png",
    "favicon-32x32.png",
  ]);

  if (swaggerAssetFiles.has(first)) {
    return "/swagger-ui/" + path.join("/");
  }

  if (first === "swagger-ui" || first === "api-doc") {
    return "/" + path.join("/");
  }
  if (first === "health" || first === "metrics") {
    return "/" + path.join("/");
  }
  // `/v1/*` is the OpenAI-compatible inference surface on the proxy (no
  // `/api/v1/` prefix). Required so client code like the /playground panel
  // can POST through `/api/proxy/v1/chat/completions` and have it land at
  // the proxy's `/v1/chat/completions`. Without this branch the catch-all
  // remapped to `/api/v1/v1/...` and produced 404.
  if (first === "v1") {
    return "/" + path.join("/");
  }
  return "/api/v1/" + path.join("/");
}

export async function GET(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = mapProxyPath(path);
  return proxyGet(req, fullPath);
}

export async function POST(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = mapProxyPath(path);
  return proxyMutate(req, fullPath, "POST");
}

export async function PUT(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = mapProxyPath(path);
  return proxyMutate(req, fullPath, "PUT");
}

export async function DELETE(req: NextRequest, context: RouteContext) {
  const { path } = await context.params;
  const fullPath = mapProxyPath(path);
  return proxyMutate(req, fullPath, "DELETE");
}
