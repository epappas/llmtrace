import { test, expect } from "@playwright/test";

// ---------------------------------------------------------------------------
// Smoke test for the dedicated /api-docs page (issue #281).
//
// Asserts:
//   1. Authenticated GET /api-docs returns 200 and renders the heading.
//   2. The sidebar exposes an "API Docs" link pointing at /api-docs.
//   3. /settings no longer embeds a Swagger UI iframe but does cross-link to
//      the new page.
//
// CI runs the dashboard with `LLMTRACE_DASHBOARD_AUTH_DISABLED=1` so the
// middleware short-circuits — same regime exercised by other e2e specs.
// We still POST through /api/auth/login to mirror auth-login.spec.ts so the
// test is portable to environments where auth is enabled.
// ---------------------------------------------------------------------------

const PROXY_BASE = process.env.LLMTRACE_PROXY_URL ?? "http://127.0.0.1:8081";

test.describe("API Docs page (issue #281)", () => {
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

  test.beforeEach(async ({ request }) => {
    // Mirror auth-login.spec.ts: fetch the seeded username, then login. The
    // CI proxy accepts any bearer (no admin_key configured) so any non-empty
    // value passes upstream validation.
    const identityRes = await request.get("/api/auth/identity");
    const identity = (await identityRes.json()) as { username: string };
    const loginRes = await request.post("/api/auth/login", {
      data: { username: identity.username, admin_key: "test-key-for-ci-stack" },
      headers: { "Content-Type": "application/json" },
    });
    expect(loginRes.status(), `login failed: ${await loginRes.text()}`).toBe(200);
  });

  test("/api-docs renders 200 with the API Endpoints heading", async ({ page }) => {
    const response = await page.goto("/api-docs");
    expect(response?.status()).toBe(200);
    await expect(
      page.getByRole("heading", { name: "API Endpoints", exact: true }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("sidebar exposes API Docs link", async ({ page }) => {
    await page.goto("/api-docs");
    const link = page.locator("aside").getByRole("link", { name: "API Docs" });
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute("href", "/api-docs");
  });

  test("/settings no longer embeds Swagger UI and links to /api-docs", async ({ page }) => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "Settings", exact: true }),
    ).toBeVisible({ timeout: 10_000 });

    // Iframe pointing at swagger-ui must be removed.
    await expect(page.locator('iframe[src*="swagger-ui"]')).toHaveCount(0);

    // Cross-link to the new home must be present.
    const crossLink = page.locator("main").getByRole("link", { name: "/api-docs" });
    await expect(crossLink).toBeVisible();
    await expect(crossLink).toHaveAttribute("href", "/api-docs");
  });
});
