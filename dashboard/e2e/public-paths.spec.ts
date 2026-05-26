import { test, expect } from "@playwright/test";

// ---------------------------------------------------------------------------
// Public-path consistency between `middleware.ts` and
// `proxy-helpers.ts::buildHeaders` (issue #276).
//
// Pre-fix, the middleware allow-listed `/api/proxy/api-doc`, `/metrics`,
// `/health`, etc. but `buildHeaders` rejected them with 401 when no
// Authorization header arrived. Result: Swagger UI iframe on `/settings`
// 401'd; `/status` could not render `/metrics`.
//
// These tests run against the live stack (the dashboard talks to the real
// proxy on `LLMTRACE_PROXY_URL`) and never short-circuit through Playwright
// `page.route` mocks — the proof must come from the real wire response.
//
// Note on CI: the CI dashboard runs with `LLMTRACE_DASHBOARD_AUTH_DISABLED=1`
// so the middleware short-circuits. That is fine for the public-path
// assertions below — every assertion below should hold REGARDLESS of
// whether the dashboard auth gate is enforcing or disabled. The regression
// test for admin-path gating is therefore scoped to "still proxies
// successfully" (no 5xx, no `auth_required` body leak) under the CI auth-
// disabled configuration. A maintainer-run live Basilica smoke covers the
// authenticated branch separately, mirroring the pattern used by
// `auth-login.spec.ts`.
// ---------------------------------------------------------------------------

const PROXY_BASE = process.env.LLMTRACE_PROXY_URL ?? "http://127.0.0.1:8081";

test.describe("Public-path consistency (issue #276)", () => {
  test.beforeAll(async ({ request }, testInfo) => {
    testInfo.setTimeout(120_000);
    const deadline = Date.now() + 120_000;
    while (true) {
      try {
        const res = await request.get(`${PROXY_BASE}/health`);
        if (res.ok()) return;
      } catch {
        // ignore — keep polling
      }
      if (Date.now() > deadline) {
        throw new Error(`Proxy not healthy at ${PROXY_BASE}/health`);
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  });

  test("unauthenticated /api/proxy/api-doc/openapi.json returns the spec", async ({ request }) => {
    const res = await request.get("/api/proxy/api-doc/openapi.json");
    expect(res.status(), `body: ${await res.text().catch(() => "<unreadable>")}`).toBe(200);
    const body = await res.text();
    expect(body).toContain("\"openapi\"");
  });

  test("unauthenticated /metrics returns Prometheus text with llmtrace_ metrics", async ({ request }) => {
    const res = await request.get("/metrics");
    expect(res.status()).toBe(200);
    const body = await res.text();
    // Any llmtrace_* counter / gauge / histogram name is sufficient proof
    // the response made it through the proxy untouched.
    expect(body).toMatch(/llmtrace_/);
  });

  test("unauthenticated /api/proxy/health returns 200", async ({ request }) => {
    const res = await request.get("/api/proxy/health");
    expect(res.status()).toBe(200);
  });

  test("admin path /api/v1/tenants does not leak the auth_required regression body", async ({ request }) => {
    // The CI dashboard runs with auth disabled, so this path proxies
    // through to the upstream and either returns the tenant list (200) or
    // a proxy-side rejection (4xx/5xx). The point of this assertion is to
    // detect a regression where `buildHeaders` 401s a path that the
    // middleware DID pass through — the previous bug shape was
    // `{"error":{"message":"auth required","type":"auth_required"}}` from
    // the dashboard layer, NOT from the proxy. We assert no such response
    // is produced for admin paths in this environment.
    const res = await request.get("/api/v1/tenants");
    // 200 (auth disabled stack) or any non-2xx that is not the dashboard-
    // synthesised auth_required body. Crucially: status 401 with the
    // dashboard's body shape is the regression.
    if (res.status() === 401) {
      const body = await res.text();
      expect(body).not.toContain("auth_required");
    }
    expect(res.status()).not.toBe(502);
  });
});
