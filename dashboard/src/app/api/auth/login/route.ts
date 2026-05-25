import { NextRequest, NextResponse } from "next/server";
import { fetchWithFallback } from "@/lib/backend";
import { sessionCookieName, SESSION_TTL_SECONDS } from "@/lib/auth";

interface LoginBody {
  admin_key?: string;
}

async function readAdminKey(req: NextRequest): Promise<string | null> {
  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const body = (await req.json().catch(() => null)) as LoginBody | null;
    return body?.admin_key?.trim() || null;
  }
  if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
    const form = await req.formData();
    const v = form.get("admin_key");
    return typeof v === "string" ? v.trim() || null : null;
  }
  return null;
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
  const adminKey = await readAdminKey(req);
  if (!adminKey) {
    return NextResponse.json({ error: "admin_key is required" }, { status: 400 });
  }

  let valid = false;
  try {
    valid = await validateAdminKey(adminKey);
  } catch (e) {
    console.error("[auth/login] validation failed:", e);
    return NextResponse.json({ error: "backend unavailable" }, { status: 502 });
  }

  if (!valid) {
    return NextResponse.json({ error: "invalid admin key" }, { status: 401 });
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
