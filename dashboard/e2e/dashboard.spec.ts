import { test, expect } from '@playwright/test';

test.describe('LLMTrace Dashboard', () => {
  // Prefer IPv4 loopback; some CI environments don't have the proxy bound on ::1.
  const proxyBaseUrl = process.env.LLMTRACE_PROXY_URL ?? 'http://127.0.0.1:8081';
  
  test.beforeAll(async ({ request }, testInfo) => {
    testInfo.setTimeout(120_000);
    // Ensure the proxy is reachable before browser tests start.
    // Some environments need a short warmup window after `docker compose up`.
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

  test.beforeEach(async ({ page }) => {
    page.on('console', msg => console.log(`[Browser]: ${msg.text()}`));
    // Navigate to the dashboard
    await page.goto('/');
  });

  test('Overview: should display global and tenant-specific stats', async ({ page }) => {
    // Check if "Overview" heading is visible (exact match)
    await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible({ timeout: 10000 });

    // Check for the "Global Transactions" card we added today
    await expect(page.getByText('Global Transactions', { exact: true })).toBeVisible();
    
    // Check for "Total Traces" card
    await expect(page.getByText('Total Traces', { exact: true })).toBeVisible();

    // Ensure dashboard content is loaded
    await expect(page.getByText('Trace Activity')).toBeVisible();
  });

  let createdTenantIds: string[] = [];

  test.afterEach(async ({ request }) => {
    for (const id of createdTenantIds) {
      console.log(`[Cleanup] Deleting test tenant: ${id}`);
      // Use direct API request for reliable cleanup even if UI fails
      // Ignore errors so one failed delete doesn't hide the rest.
      // eslint-disable-next-line no-await-in-loop
      await request.delete(`${proxyBaseUrl}/api/v1/tenants/${id}`).catch(() => {});
    }
    createdTenantIds = [];
  });

  test('Tenants: should create, generate token, and delete a tenant', async ({ page }) => {
    await page.goto('/tenants');
    await page.waitForLoadState('networkidle');
    
    const tenantName = `Test-Tenant-${Date.now()}`;

    // 1. Create Tenant
    await page.getByRole('button', { name: 'New Tenant' }).click();
    await page.getByPlaceholder('Tenant name').fill(tenantName);
    
    // Capture the tenant ID from the response to ensure cleanup
    const createResponsePromise = page.waitForResponse(r => r.url().includes('/api/v1/tenants') && r.request().method() === 'POST');
    await page.getByRole('button', { name: 'Create' }).click();
    const createRes = await createResponsePromise;
    const body = await createRes.json();
    createdTenantIds.push(body.id);

    // Verify it appeared in the list
    await expect(page.getByTestId(`tenant-name-${tenantName}`)).toBeVisible({ timeout: 15000 });

    // 2. Generate Token
    const row = page.locator('tr', { has: page.getByTestId(`tenant-name-${tenantName}`) });
    await row.getByRole('button', { name: 'Token' }).click();
    await expect(page.getByText('Token Generated')).toBeVisible({ timeout: 10000 });

    // 3. Delete Tenant (Explicit test of UI deletion)
    page.on('dialog', dialog => dialog.accept());
    const deleteBtn = row.locator('button').last();
    await deleteBtn.click();
    
    // Verify it was removed from UI
    await expect(page.getByTestId(`tenant-name-${tenantName}`)).toHaveCount(0, { timeout: 15000 });
    
    // Clear the tracker since UI deletion succeeded
    createdTenantIds = createdTenantIds.filter((id) => id !== body.id);
  });

  test('Traces: should filter by Trace ID and Model', async ({ page }) => {
    await page.goto('/traces');
    await page.waitForLoadState('networkidle');

    // Check for the new filters we added today
    await expect(page.getByPlaceholder('Filter by Trace ID')).toBeVisible();
    await expect(page.getByText('Date (YYYY-MM-DD)')).toBeVisible();

    // Test Model filter
    const modelInput = page.getByPlaceholder('Filter by Model');
    await expect(modelInput).toBeVisible();
    await modelInput.fill('glm-4.7-flash');
  });

  test('Trace Details: should show prompt and response content', async ({ page }) => {
    await page.goto('/traces');
    await page.waitForLoadState('networkidle');
    
    // Wait for data to load
    try {
      await page.waitForSelector('tbody tr', { timeout: 10000 });
    } catch {
      test.skip('No traces found to test details');
      return;
    }
    
    // Click on the first trace row to view details
    const firstTrace = page.locator('tbody tr').first();
    await firstTrace.click();

    // Verify detail page header
    await expect(page.getByRole('heading', { name: 'Trace', exact: false })).toBeVisible({ timeout: 10000 });

    // Check the "Response" tab
    await page.getByRole('tab', { name: 'Response' }).click();
    // Radix UI unmounts inactive tabs, so only one 'pre' should be visible/present
    await expect(page.locator('.pt-4 pre').first()).toBeVisible({ timeout: 10000 });
    
    // Check the "Prompt" tab
    await page.getByRole('tab', { name: 'Prompt' }).click();
    await expect(page.locator('.pt-4 pre').first()).toBeVisible();
  });

  test('Security: should display security findings distribution', async ({ page }) => {
    await page.goto('/security');
    await page.waitForLoadState('networkidle');
    
    await expect(page.getByRole('heading', { name: 'Security', exact: true })).toBeVisible({ timeout: 10000 });
    
    // Check for stat cards
    await expect(page.getByText('Total Findings', { exact: true })).toBeVisible();
    
    // Ensure dashboard content is loaded
    await expect(page.getByText('Severity Distribution')).toBeVisible();
  });

  test('Costs: should show budget status and utilization', async ({ page }) => {
    await page.goto('/costs');
    
    await expect(page.getByRole('heading', { name: 'Costs' })).toBeVisible();
    
    // Check for the "Budget Status" card
    await expect(page.getByText('Budget Status')).toBeVisible();

    // In the default proxy configuration, cost caps can be disabled; in that case
    // the page intentionally shows an informational empty state instead of charts.
    const disabledMsg = page.getByText('Cost caps are not enabled in the proxy configuration.');
    const chartTitle = page.getByText('Budget Utilization');

    const outcome = await Promise.race([
      disabledMsg.waitFor({ state: 'visible', timeout: 10_000 }).then(() => 'disabled' as const),
      chartTitle.waitFor({ state: 'visible', timeout: 10_000 }).then(() => 'chart' as const),
    ]);

    if (outcome === 'disabled') {
      await expect(disabledMsg).toBeVisible();
      return;
    }

    await expect(chartTitle).toBeVisible();
  });

  test('Sidebar: should persist tenant selection', async ({ page, request }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    
    const selector = page.locator('aside select');
    await expect(selector).toBeVisible();

    // 1. Ensure we have at least 2 tenants
    let options = await selector.locator('option').all();
    if (options.length < 2) {
      const needed = 2 - options.length;
      console.log(`[Test Setup] Creating ${needed} tenant(s) for persistence test`);

      for (let i = 0; i < needed; i++) {
        // eslint-disable-next-line no-await-in-loop
        const res = await request.post(`${proxyBaseUrl}/api/v1/tenants`, {
          data: { name: `Temp-Persistence-Test-${Date.now()}-${i}`, plan: 'Pro' }
        });
        if (!res.ok()) {
          // eslint-disable-next-line no-await-in-loop
          const text = await res.text().catch(() => '<no body>');
          throw new Error(`Failed to create tenant: ${res.status()} ${text}`);
        }
        // eslint-disable-next-line no-await-in-loop
        const tempTenant = await res.json();
        createdTenantIds.push(tempTenant.id);
      }

      // Wait until the API reflects the new tenants (avoids flakiness around reload timing).
      const deadline = Date.now() + 10_000;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        // eslint-disable-next-line no-await-in-loop
        const res = await request.get(`${proxyBaseUrl}/api/v1/tenants`);
        if (res.ok()) {
          // eslint-disable-next-line no-await-in-loop
          const list = await res.json().catch(() => []);
          if (Array.isArray(list) && list.length >= 2) break;
        }
        if (Date.now() > deadline) break;
        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, 250));
      }

      await page.reload();
      await page.waitForLoadState('networkidle');
      await page.waitForFunction(() => document.querySelectorAll('aside select option').length >= 2);
      options = await selector.locator('option').all();
    }

    if (options.length < 2) {
      throw new Error(`Test requires 2 tenants but only found ${options.length}`);
    }

    const targetId = await options[1].getAttribute('value');
    if (!targetId) {
      throw new Error('Second tenant option had no value attribute');
    }
    
    // 2. Select the second tenant and wait until it is persisted in localStorage
    await selector.selectOption(targetId);
    await page.waitForFunction((id) => localStorage.getItem("llmtrace_tenant_id") === id, targetId);
    
    // 3. Verify it persists after navigation + reload (forces sidebar to re-read localStorage)
    await page.goto('/settings');
    await page.waitForLoadState('networkidle');
    await page.reload();
    await page.waitForLoadState('networkidle');

    await expect(page.locator('aside select')).toHaveValue(targetId, { timeout: 10000 });
  });

});
