import { NextRequest, NextResponse } from "next/server";
import { sessionCookieName, isAuthDisabled } from "./lib/auth";

// Paths that bypass the auth gate entirely. `/health` MUST stay open because
// Basilica's k8s readiness probe hits it; `/login` and `/api/auth/*` are how
// the user obtains a session in the first place; `/_next/*` and the standard
// static asset paths must be reachable so the login page itself can render.
const PUBLIC_PREFIXES: readonly string[] = [
  "/login",
  "/api/auth/",
  "/health",
  "/metrics",
  "/_next/",
  "/api-doc",
  "/api/proxy/swagger-ui",
  "/api/proxy/api-doc",
  "/favicon.ico",
  "/robots.txt",
  "/sitemap.xml",
];

const STATIC_FILE_RE = /\.(?:png|jpg|jpeg|gif|svg|ico|webp|avif|css|js|map|woff|woff2|ttf|otf|eot|json|txt)$/i;

function isPublicPath(pathname: string): boolean {
  if (STATIC_FILE_RE.test(pathname)) return true;
  return PUBLIC_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(prefix));
}

function isJsonRoute(req: NextRequest): boolean {
  if (req.nextUrl.pathname.startsWith("/api/")) return true;
  const accept = req.headers.get("accept") ?? "";
  return accept.includes("application/json") && !accept.includes("text/html");
}

function redirectToLogin(req: NextRequest): NextResponse {
  const url = req.nextUrl.clone();
  const next = `${req.nextUrl.pathname}${req.nextUrl.search}`;
  url.pathname = "/login";
  url.search = `?next=${encodeURIComponent(next)}`;
  return NextResponse.redirect(url);
}

function unauthorizedJson(): NextResponse {
  return NextResponse.json({ error: "auth required" }, { status: 401 });
}

export function middleware(req: NextRequest): NextResponse {
  const { pathname } = req.nextUrl;

  if (isPublicPath(pathname)) return NextResponse.next();
  if (isAuthDisabled()) return NextResponse.next();

  const cookieName = sessionCookieName(req.headers.get("host"));
  const session = req.cookies.get(cookieName)?.value;

  if (!session) {
    return isJsonRoute(req) ? unauthorizedJson() : redirectToLogin(req);
  }

  // Forward the session as a Bearer token so server route handlers
  // (proxyGet / proxyMutate) pick it up via the existing `authorization`
  // header path. We do not expose the cookie value to the client.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("authorization", `Bearer ${session}`);
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
