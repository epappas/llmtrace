import { test, expect, type APIRequestContext } from "@playwright/test";

// ---------------------------------------------------------------------------
// Public-path consistency between `middleware.ts` and
// `proxy-helpers.ts::buildHeaders` (issues #276, #280).
//
// History:
//   - #276: middleware and `buildHeaders` disagreed on which paths are
//     genuinely public. Spec consolidated them via `UPSTREAM_PUBLIC_PATHS`.
//   - #280: #276 incorrectly listed `/metrics` as public. The proxy's
//     auth-middleware (`crates/llmtrace-proxy/src/auth.rs`) only exempts
//     `/health`, `/swagger-ui`, `/api-doc`. Per R10, `/metrics` requires
//     a bearer. We removed `/metrics` from `UPSTREAM_PUBLIC_PATHS` and
//     the dashboard now injects the session cookie as Bearer when
//     forwarding to the proxy.
//
// These tests run against the live stack (the dashboard talks to the real
// proxy on `LLMTRACE_PROXY_URL`) and never short-circuit through Playwright
// `page.route` mocks — the proof must come from the real wire response.
//
// CI environment note: the CI dashboard runs with
// `LLMTRACE_DASHBOARD_AUTH_DISABLED=1` AND the CI proxy runs with
// `auth.enabled = false` (no admin_key configured). So both layers are
// permissive in CI. Tests therefore assert the contract shape that
// holds across both modes — see per-test comments. The maintainer-run
// live Basilica smoke covers the auth-enforced branch separately,
// mirroring the pattern used by `auth-login.spec.ts`.
// ---------------------------------------------------------------------------

const PROXY_BASE = process.env.LLMTRACE_PROXY_URL ?? "http://127.0.0.1:8081";

async function loginWithSession(request: APIRequestContext): Promise<void> {
  // Fetch the seeded username via the public identity endpoint so this
  // mirrors whatever the stack was provisioned with (defaults to "admin").
  const identityRes = await request.get("/api/auth/identity");
  const identity = (await identityRes.json()) as { username: string };

  // The CI proxy accepts any bearer (no admin_key configured), so any
  // non-empty key validates. In auth-enforced deployments the maintainer
  // smoke supplies a real admin key. Either way, the request fixture
  // persists the resulting Set-Cookie for follow-up calls.
  const res = await request.post("/api/auth/login", {
    data: { username: identity.username, admin_key: "test-key-for-ci-stack" },
    headers: { "Content-Type": "application/json" },
  });
  expect(res.status(), `login response: ${await res.text()}`).toBe(200);
}

test.describe("Public-path consistency (issues #276, #280)", () => {
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

  test("unauthenticated /api/proxy/health returns 200", async ({ request }) => {
    const res = await request.get("/api/proxy/health");
    expect(res.status()).toBe(200);
  });

  // Issue #280: /metrics is NOT on the public allow-list any more.
  //
  // With dashboard auth ENFORCED (production, maintainer smoke): the
  // middleware short-circuits the cookieless request to 401 (JSON) or
  // 302 /login (HTML). With dashboard auth DISABLED (CI), the middleware
  // passes through and the proxy answers — in CI the proxy itself runs
  // auth-disabled, so it returns 200 + metrics text.
  //
  // The regression we are guarding against is: dashboard returns the
  // synthesised `auth_required` body (the #280 failure mode) or a 502
  // from `proxy-helpers`. Both are non-contract.
  test("unauthenticated /metrics never leaks the dashboard auth_required body", async ({ request }) => {
    const res = await request.get("/metrics", {
      headers: { Accept: "application/json" },
    });
    const body = await res.text().catch(() => "");
    // Acceptable outcomes:
    //   200 → CI auth-disabled stack, real proxy response with llmtrace_ metrics
    //   401 → dashboard middleware rejected the cookieless JSON request
    //   302 → dashboard middleware redirected (when Accept negotiates HTML)
    // Unacceptable: the dashboard's pre-fix `auth_required` body shape
    // (proof of regression to the #276 mis-spec), or a 5xx proxy failure.
    expect(body).not.toContain("auth_required");
    expect(res.status()).not.toBe(502);
    expect([200, 302, 401]).toContain(res.status());
    if (res.status() === 200) {
      expect(body).toMatch(/llmtrace_/);
    }
  });

  // Issue #280: with a valid session cookie the dashboard middleware
  // injects `Authorization: Bearer <session>` and the request reaches
  // the proxy as an authenticated call — proxy returns 200 + metrics.
  test("authenticated /metrics returns Prometheus text with llmtrace_ metrics", async ({ request }) => {
    await loginWithSession(request);
    const res = await request.get("/metrics");
    expect(res.status(), `body: ${await res.text().catch(() => "<unreadable>")}`).toBe(200);
    const body = await res.text();
    // Any llmtrace_* counter / gauge / histogram name is sufficient proof
    // the response made it through the proxy untouched.
    expect(body).toMatch(/llmtrace_/);
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
