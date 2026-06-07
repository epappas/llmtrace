import { NextRequest, NextResponse } from "next/server";
import { sessionCookieName, SESSION_TTL_SECONDS, isAuthDisabled } from "@/lib/auth";
import { verifySsoToken } from "@/lib/sso-token";

// node:crypto (HMAC) — force the Node runtime, never edge.
export const runtime = "nodejs";

/**
 * GET /api/auth/sso?token=…
 *
 * One-click sign-in handoff from the LLMTrace portal. The portal mints a
 * short-lived token signed with this instance's admin key; we verify it
 * against `LLMTRACE_AUTH_ADMIN_KEY` (the same per-instance secret) and, on
 * success, set the normal session cookie and bounce to the dashboard home.
 *
 * The admin key is never carried in the URL — only its HMAC signature is — and
 * is never shown to the user; it lands directly in the HttpOnly session cookie,
 * exactly as a manual login would. This route is public (see middleware's
 * `/api/auth/` prefix) because it runs before a session exists.
 */
export function GET(req: NextRequest): NextResponse {
  const token = req.nextUrl.searchParams.get("token");

  // Local-dev escape hatch: auth disabled means no session is required at all.
  if (isAuthDisabled()) return seeOther("/");

  if (!token) return rejectToLogin("missing_token");

  const adminKey = process.env.LLMTRACE_AUTH_ADMIN_KEY ?? "";
  const result = verifySsoToken(token, adminKey, Math.floor(Date.now() / 1000));
  if (!result.ok) return rejectToLogin(result.reason);

  const res = seeOther("/");
  res.cookies.set({
    name: sessionCookieName(req.headers.get("host")),
    value: adminKey,
    httpOnly: true,
    secure: isSecure(req),
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
  return res;
}

function isSecure(req: NextRequest): boolean {
  if (req.nextUrl.protocol === "https:") return true;
  return req.headers.get("x-forwarded-proto") === "https";
}

/**
 * 303 with a RELATIVE Location. The browser resolves it against the public
 * request URL, so it works behind Basilica's ingress. An absolute
 * `NextResponse.redirect(req.nextUrl)` would, in the Node runtime, serialise
 * the container's internal host (`0.0.0.0:3000`) and send the browser to a
 * dead address — the dashboard's middleware redirects are relative for the
 * same reason.
 */
function seeOther(location: string): NextResponse {
  return new NextResponse(null, { status: 303, headers: { Location: location } });
}

function rejectToLogin(reason: string): NextResponse {
  console.warn("[auth/sso] rejected:", reason);
  return seeOther("/login?error=sso");
}
