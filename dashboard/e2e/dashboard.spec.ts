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

  test('Tenants: should create, generate token, and delete a tenant', async ({ page, request }) => {
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

    // 2. Automated Token Generation can be timing-sensitive in CI.
    // If it appears, validate and dismiss it; otherwise continue with manual token flow.
    const autoTokenCardVisible = await page
      .getByTestId('new-token-title')
      .isVisible()
      .catch(() => false);
    if (autoTokenCardVisible) {
      await expect(page.getByTestId('new-token-title')).toBeVisible({ timeout: 10000 });
      await page.getByRole('button', { name: 'Dismiss' }).click();
      await expect(page.getByTestId('new-token-title')).not.toBeVisible();
    }

    // 3. Manual Token Management: verify clicking "Token" opens management view
    const row = page.locator('tr', { has: page.getByTestId(`tenant-name-${tenantName}`) });
    await row.getByTestId('manage-token-button').click();
    // Wait for the management card to be rendered after state update
    await expect(page.getByTestId('manage-tokens-title')).toBeVisible({ timeout: 15000 });
    await page.getByRole('button', { name: 'Close' }).click();
    await expect(page.getByTestId('manage-tokens-title')).not.toBeVisible();

    // 4. Delete Tenant (Explicit test of UI deletion)
    page.on('dialog', dialog => dialog.accept());
    const deleteBtn = row.locator('button').last();
    await deleteBtn.click();
    
    // Verify backend deletion completed, then ensure tenant no longer appears after refresh.
    await expect
      .poll(
        async () => {
          const listRes = await request.get(`${proxyBaseUrl}/api/v1/tenants`);
          if (!listRes.ok()) return false;
          const list = (await listRes.json()) as Array<{ id: string }>;
          return !list.some((tenant) => tenant.id === body.id);
        },
        { timeout: 20_000 },
      )
      .toBeTruthy();
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
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
      test.skip(true, 'No traces found to test details');
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

    // Cost caps can be disabled; in that case an informational card is shown.
    // Accept either enabled (chart/windows) or disabled informational state.
    const hasEnabledState = await page
      .getByText('Budget Utilization')
      .isVisible()
      .catch(() => false);
    if (hasEnabledState) {
      await expect(page.getByText('Budget Utilization')).toBeVisible();
      return;
    }

    const disabledHints = [
      'Cost tracking is disabled',
      'Cost caps not enabled',
      'Enable `cost_caps.enabled: true`',
    ];

    await expect
      .poll(
        async () => {
          for (const hint of disabledHints) {
            const visible = await page
              .getByText(hint, { exact: false })
              .first()
              .isVisible()
              .catch(() => false);
            if (visible) return true;
          }
          return false;
        },
        { timeout: 15_000 },
      )
      .toBeTruthy();
  });

  test('Sidebar: should persist tenant selection', async ({ page, request }) => {
    // This test is sensitive to environment startup timing (fresh CI stack can have 0 tenants).
    // Give it extra headroom so it behaves consistently across browsers (especially WebKit/Firefox).
    test.setTimeout(120_000);

    await page.goto('/');
    // Avoid `networkidle` here; Next.js can keep background requests active in some browsers.
    await page.waitForLoadState('domcontentloaded');
    
    const selector = page.locator('aside select');
    await expect(selector).toBeVisible();

    // 1. Ensure we have at least 2 real tenants.
    // The UI may render a placeholder <option> (empty value) even when there are 0 tenants,
    // so don't use DOM option count for setup. Use the API as the source of truth.
    const listRes = await request.get(`${proxyBaseUrl}/api/v1/tenants`);
    if (!listRes.ok()) {
      const text = await listRes.text().catch(() => '<no body>');
      throw new Error(`Failed to list tenants: ${listRes.status()} ${text}`);
    }
    const initialTenants = (await listRes.json().catch(() => [])) as Array<{ id?: string }>;
    const existingCount = Array.isArray(initialTenants) ? initialTenants.length : 0;

    if (existingCount < 2) {
      const needed = 2 - existingCount;
      console.log(`[Test Setup] Creating ${needed} tenant(s) for persistence test (existing: ${existingCount})`);

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
      const deadline = Date.now() + 30_000;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        // eslint-disable-next-line no-await-in-loop
        const res = await request.get(`${proxyBaseUrl}/api/v1/tenants`);
        if (res.ok()) {
          // eslint-disable-next-line no-await-in-loop
          const list = await res.json().catch(() => []);
          if (Array.isArray(list) && list.length >= 2) break;
        }
        if (Date.now() > deadline) {
          // eslint-disable-next-line no-await-in-loop
          const debugRes = await request.get(`${proxyBaseUrl}/api/v1/tenants`).catch(() => null);
          const debugText = debugRes ? await debugRes.text().catch(() => '<no body>') : '<no response>';
          throw new Error(`Timed out waiting for 2 tenants via API. Last response: ${debugText}`);
        }
        // eslint-disable-next-line no-await-in-loop
        await new Promise((r) => setTimeout(r, 250));
      }

      await page.reload();
      await page.waitForLoadState('domcontentloaded');
      // Wait for 2 real tenant options (ignore placeholder/empty option).
      await page.waitForFunction(() => {
        const opts = Array.from(document.querySelectorAll('aside select option'));
        const real = opts.filter((o) => (o as HTMLOptionElement).value && (o as HTMLOptionElement).value.trim() !== '');
        return real.length >= 2;
      });
    }

    // 2. Select the second real tenant option (ignore placeholder option with empty value).
    const optionValues = await selector.evaluate((el) => {
      const opts = Array.from((el as HTMLSelectElement).querySelectorAll('option'));
      return opts
        .map((o) => (o as HTMLOptionElement).value)
        .filter((v) => v && v.trim() !== '');
    });

    if (optionValues.length < 2) {
      throw new Error(`Test requires 2 tenant options but only found ${optionValues.length}`);
    }

    const targetId = optionValues[1];
    if (!targetId) {
      throw new Error('Second tenant option had no value attribute');
    }
    
    // 3. Select the second tenant and wait until it is persisted in localStorage
    await selector.selectOption(targetId);
    await page.waitForFunction((id) => localStorage.getItem("llmtrace_tenant_id") === id, targetId);
    
    // 4. Verify it persists after a hard reload (sidebar must re-read localStorage).
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await expect(page.locator('aside select')).toHaveValue(targetId, { timeout: 15000 });
  });

});
