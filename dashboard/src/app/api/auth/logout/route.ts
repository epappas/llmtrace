import { NextRequest, NextResponse } from "next/server";
import { sessionCookieName } from "@/lib/auth";

export async function POST(req: NextRequest): Promise<NextResponse> {
  const res = NextResponse.json({ ok: true });
  res.cookies.set({
    name: sessionCookieName(req.headers.get("host")),
    value: "",
    httpOnly: true,
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
  return res;
}
