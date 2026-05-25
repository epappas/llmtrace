import { NextRequest, NextResponse } from "next/server";
import { fetchWithFallback } from "@/lib/backend";
import {
  sessionCookieName,
  SESSION_TTL_SECONDS,
  expectedAdminUsername,
  usernameMatches,
} from "@/lib/auth";

interface LoginBody {
  username?: string;
  admin_key?: string;
}

interface SubmittedCredentials {
  username: string | null;
  adminKey: string | null;
}

async function readCredentials(req: NextRequest): Promise<SubmittedCredentials> {
  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const body = (await req.json().catch(() => null)) as LoginBody | null;
    return {
      username: body?.username?.trim() || null,
      adminKey: body?.admin_key?.trim() || null,
    };
  }
  if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
    const form = await req.formData();
    const u = form.get("username");
    const k = form.get("admin_key");
    return {
      username: typeof u === "string" && u.trim() ? u.trim() : null,
      adminKey: typeof k === "string" && k.trim() ? k.trim() : null,
    };
  }
  return { username: null, adminKey: null };
}

async function validateAdminKey(adminKey: string): Promise<boolean> {
  const { response } = await fetchWithFallback("/api/v1/auth/keys", {
    method: "GET",
    headers: { Authorization: `Bearer ${adminKey}` },
    cache: "no-store",
  });
  return response.ok;
}

function isSecure(req: NextRequest): boolean {
  if (req.nextUrl.protocol === "https:") return true;
  return req.headers.get("x-forwarded-proto") === "https";
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const { username, adminKey } = await readCredentials(req);
  if (!username || !adminKey) {
    return NextResponse.json(
      { error: "username and admin_key are required" },
      { status: 400 },
    );
  }

  // Username check first (fast, no upstream call). On mismatch return the
  // same 401 shape as a bad key so we don't leak which half was wrong.
  if (!usernameMatches(username, expectedAdminUsername())) {
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  let valid = false;
  try {
    valid = await validateAdminKey(adminKey);
  } catch (e) {
    console.error("[auth/login] validation failed:", e);
    return NextResponse.json({ error: "backend unavailable" }, { status: 502 });
  }

  if (!valid) {
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }

  const res = NextResponse.json({ ok: true });
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
