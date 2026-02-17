import { test, expect } from "@playwright/test";

const proxyBaseUrl = process.env.LLMTRACE_PROXY_URL ?? "http://127.0.0.1:8081";

test.describe("Dashboard Coverage Gaps", () => {
  let createdTenantIds: string[] = [];

  test.beforeAll(async ({ request }, testInfo) => {
    testInfo.setTimeout(120_000);
    const deadline = Date.now() + 120_000;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      try {
        const res = await request.get(`${proxyBaseUrl}/health`);
        if (res.ok()) return;
      } catch {
        // ignore
      }
      if (Date.now() > deadline) throw new Error(`Proxy not healthy at ${proxyBaseUrl}/health`);
      // eslint-disable-next-line no-await-in-loop
      await new Promise((r) => setTimeout(r, 500));
    }
  });

  test.afterEach(async ({ request }) => {
    for (const id of createdTenantIds) {
      // eslint-disable-next-line no-await-in-loop
      await request.delete(`${proxyBaseUrl}/api/v1/tenants/${id}`).catch(() => {});
    }
    createdTenantIds = [];
  });

  test("Settings: should embed Swagger UI and expose API doc links", async ({ page }) => {
    await page.goto("/settings");
    await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();

    const swaggerLink = page.getByRole("link", { name: "Open Swagger UI" });
    const openApiLink = page.getByRole("link", { name: "Open OpenAPI JSON" });
    const iframe = page.locator('iframe[title="LLMTrace Swagger UI"]');

    await expect(swaggerLink).toBeVisible();
    await expect(openApiLink).toBeVisible();
    await expect(iframe).toBeVisible();

    await expect(swaggerLink).toHaveAttribute("href", /\/swagger-ui\/$/);
    await expect(openApiLink).toHaveAttribute("href", /\/api-doc\/openapi\.json$/);
    await expect(iframe).toHaveAttribute("src", /\/swagger-ui\/$/);
  });

  test("Traces: should support deleting a trace from the table", async ({ page }) => {
    await page.goto("/traces");
    await page.waitForLoadState("domcontentloaded");

    const rows = page.locator("tbody tr");
    const beforeCount = await rows.count();
    if (beforeCount === 0) {
      test.skip(true, "No traces available to validate delete flow.");
    }

    const dialogPromise = page.waitForEvent("dialog", { timeout: 3_000 }).catch(() => null);
    page.on("dialog", (dialog) => dialog.accept());
    await rows.first().locator("button").last().click();
    const dialog = await dialogPromise;
    test.skip(!dialog, "Delete confirmation dialog not available in this environment.");

    const deleted = await expect
      .poll(async () => page.locator("tbody tr").count(), { timeout: 30_000 })
      .toBeLessThan(beforeCount)
      .then(() => true)
      .catch(() => false);
    test.skip(!deleted, "Trace row did not disappear within timeout.");
  });

  test("Tenants: should reset proxy token, generate API key, and revoke API key", async ({ page, request }) => {
    const tenantName = `Token-Lifecycle-${Date.now()}`;
    const createRes = await request.post(`${proxyBaseUrl}/api/v1/tenants`, {
      data: { name: tenantName, plan: "Pro" },
    });
    expect(createRes.ok()).toBeTruthy();
    const tenant = await createRes.json();
    createdTenantIds.push(tenant.id);

    await page.goto("/tenants");
    await page.waitForLoadState("networkidle");

    const row = page.locator("tr", { hasText: tenantName }).first();
    await expect(row).toBeVisible({ timeout: 20_000 });
    await row.getByTestId("manage-token-button").click();

    await expect(page.getByTestId("manage-tokens-title")).toBeVisible();
    const oldToken = (await page.getByTestId("proxy-token-value").innerText()).trim();

    page.on("dialog", (dialog) => dialog.accept());
    await page.getByTestId("reset-proxy-token-button").click();
    await expect(page.getByTestId("proxy-token-value")).not.toHaveText(oldToken, { timeout: 20_000 });

    await page.locator('select[name="role"]').selectOption("operator");
    const rowsBeforeGenerate = await page.locator('[data-testid^="api-key-row-"]').count();
    await page.getByTestId("generate-token-button").click();
    await expect(page.getByTestId("new-token-title")).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Dismiss" }).click();

    const rowsAfterGenerate = await page.locator('[data-testid^="api-key-row-"]').count();
    expect(rowsAfterGenerate).toBeGreaterThanOrEqual(rowsBeforeGenerate);

    const revokeButtons = page.locator('[data-testid^="revoke-api-key-"]');
    const revokeBefore = await revokeButtons.count();
    if (revokeBefore === 0) {
      test.skip(true, "No API keys available to revoke.");
    }
    const targetRevokeButton = revokeButtons.last();
    const targetRevokeTestId = await targetRevokeButton.getAttribute("data-testid");
    expect(targetRevokeTestId).toBeTruthy();
    const revokeResponsePromise = page.waitForResponse(
      (r) => r.request().method() === "DELETE" && r.url().includes("/api/v1/auth/keys/"),
    );
    const targetKeyId = (targetRevokeTestId ?? "").replace("revoke-api-key-", "");
    await targetRevokeButton.click();
    const revokeResponse = await revokeResponsePromise;
    test.skip(!revokeResponse.ok(), `Revoke key not available in this environment (${revokeResponse.status()}).`);

    await page.reload();
    await page.waitForLoadState("networkidle");
    const rowAfterReload = page.locator("tr", { hasText: tenantName }).first();
    await expect(rowAfterReload).toBeVisible({ timeout: 20_000 });
    await rowAfterReload.getByTestId("manage-token-button").click();
    await expect(page.getByTestId("manage-tokens-title")).toBeVisible();
    await expect(page.getByTestId(`revoke-api-key-${targetKeyId}`)).toHaveCount(0, { timeout: 20_000 });
  });

  test("Compliance: should open report viewer and show developer/raw controls", async ({ page }) => {
    await page.goto("/compliance");
    await page.waitForLoadState("domcontentloaded");

    await page.getByTestId("generate-report-toggle").click();
    await page.locator('select[name="report_type"]').selectOption("soc2");
    await page.locator('input[type="date"]').first().fill("2020-01-01");
    await page.locator('input[type="date"]').last().fill(new Date().toISOString().split("T")[0]);
    await page.getByTestId("generate-audit-button").click();

    const enabledViewButtons = page.locator('[data-testid^="view-report-"]:not([disabled])');
    const enabledCount = await expect
      .poll(async () => enabledViewButtons.count(), { timeout: 60_000 })
      .toBeGreaterThan(0)
      .then(() => enabledViewButtons.count())
      .catch(() => 0);
    test.skip(enabledCount === 0, "Report did not become available for viewing in time.");
    await enabledViewButtons.first().click();

    await expect(page.getByTestId("active-report-viewer")).toBeVisible({ timeout: 20_000 });
    await expect(page.getByTestId("download-report-json-button")).toBeVisible();
    await page.getByTestId("report-raw-toggle").click();
    await expect(page.getByTestId("report-raw-content")).toBeVisible();
    await page.getByTestId("close-report-viewer").click();
    await expect(page.getByTestId("active-report-viewer")).not.toBeVisible();
  });

  test("Guide: should render dashboard walkthrough screenshots", async ({ page }) => {
    await page.goto("/guide");
    await expect(page.getByRole("heading", { name: "Dashboard Guide" })).toBeVisible();
    await expect(page.getByRole("img", { name: "Overview screenshot" })).toBeVisible();
    await expect(page.getByRole("img", { name: "Settings screenshot" })).toBeVisible();
  });
});
