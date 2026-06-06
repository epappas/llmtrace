// ---------------------------------------------------------------------------
// Portal → dashboard SSO handoff token
// ---------------------------------------------------------------------------
//
// One-click "Open dashboard" works by the portal minting a short-lived token
// that this dashboard verifies, then establishing the normal session cookie.
//
// The token is HMAC-SHA256 signed with the per-instance admin key — a secret
// already present on BOTH sides (the portal holds it in its vault; this
// dashboard receives it as `LLMTRACE_AUTH_ADMIN_KEY`). Because the secret is
// per-instance, a token minted for one instance only verifies on that
// instance's dashboard. The admin key itself never leaves either server: only
// the HMAC signature travels in the redirect URL.
//
// This module is duplicated verbatim in the Portal repo (lib/sso-token.ts).
// The two copies MUST stay byte-identical or tokens won't verify — keep the
// payload shape, field order, and base64url encoding in lock-step.

import { createHmac, timingSafeEqual } from "node:crypto";

/** Single-purpose tag baked into the payload so a token can't be repurposed. */
const PURPOSE = "dashboard_sso";

/** Default token lifetime. Short: the token is redeemed immediately on click. */
export const SSO_TOKEN_TTL_SECONDS = 90;

interface SsoPayload {
  /** purpose tag */
  p: string;
  /** expiry, unix seconds */
  exp: number;
}

function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(s: string): Buffer {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function sign(body: string, secret: string): string {
  return base64url(createHmac("sha256", secret).update(body).digest());
}

/**
 * Mint a signed SSO token valid for `ttlSeconds`. `nowSeconds` is passed in
 * (not read from the clock) so the function is pure and unit-testable.
 */
export function mintSsoToken(
  secret: string,
  nowSeconds: number,
  ttlSeconds: number = SSO_TOKEN_TTL_SECONDS,
): string {
  const payload: SsoPayload = { p: PURPOSE, exp: nowSeconds + ttlSeconds };
  const body = base64url(Buffer.from(JSON.stringify(payload), "utf8"));
  return `${body}.${sign(body, secret)}`;
}

export type SsoVerifyResult = { ok: true } | { ok: false; reason: string };

/**
 * Verify a token against `secret` at `nowSeconds`. Returns a tagged result
 * rather than throwing so the caller can branch without try/catch. The
 * signature check is constant-time.
 */
export function verifySsoToken(token: string, secret: string, nowSeconds: number): SsoVerifyResult {
  if (!secret) return { ok: false, reason: "no_secret" };
  const dot = token.indexOf(".");
  if (dot <= 0 || dot === token.length - 1) return { ok: false, reason: "malformed" };

  const body = token.slice(0, dot);
  const sig = Buffer.from(token.slice(dot + 1));
  const expected = Buffer.from(sign(body, secret));
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) {
    return { ok: false, reason: "bad_signature" };
  }

  let payload: SsoPayload;
  try {
    payload = JSON.parse(base64urlDecode(body).toString("utf8")) as SsoPayload;
  } catch {
    return { ok: false, reason: "bad_payload" };
  }
  if (payload.p !== PURPOSE) return { ok: false, reason: "bad_purpose" };
  if (typeof payload.exp !== "number" || payload.exp < nowSeconds) return { ok: false, reason: "expired" };
  return { ok: true };
}
