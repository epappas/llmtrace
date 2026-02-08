import { test, expect } from '@playwright/test';

test.describe('LLMTrace Dashboard', () => {
  
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

  test('Tenants: should create, generate token, and delete a tenant', async ({ page }) => {
    await page.goto('/tenants');
    await page.waitForLoadState('networkidle');
    
    const tenantName = `Test-Tenant-${Date.now()}`;

    // 1. Create Tenant
    await page.getByRole('button', { name: 'New Tenant' }).click();
    await page.getByPlaceholder('Tenant name').fill(tenantName);
    await page.getByRole('button', { name: 'Create' }).click();

    // Verify it appeared in the list
    await expect(page.getByTestId(`tenant-name-${tenantName}`)).toBeVisible({ timeout: 15000 });

    // 2. Generate Token
    // Find the row with our tenant and click the "Token" button
    const row = page.locator('tr', { has: page.getByTestId(`tenant-name-${tenantName}`) });
    await row.getByRole('button', { name: 'Token' }).click();

    // Verify Token Generated card appeared and key is visible
    await expect(page.getByText('Token Generated')).toBeVisible({ timeout: 10000 });
    await expect(page.locator('code').filter({ hasText: 'llmt_' })).toBeVisible();

    // 3. Delete Tenant
    // Handle the browser confirmation dialog
    page.on('dialog', dialog => dialog.accept());
    
    // Click the delete button (trash icon) and wait for the API response
    const deleteBtn = row.locator('button').last();
    const deleteResponsePromise = page.waitForResponse(response => 
      response.url().includes('/api/v1/tenants/') && response.request().method() === 'DELETE'
    );
    await deleteBtn.click();
    const deleteResponse = await deleteResponsePromise;
    expect(deleteResponse.ok()).toBeTruthy();

    // Give the backend a moment to finalize
    await page.waitForTimeout(2000);

    // Reload page to confirm persistence of deletion
    await page.reload();
    await page.waitForLoadState('networkidle');

    // Verify it was removed (specifically check the table body)
    const tableBody = page.locator('tbody');
    await expect(tableBody.getByTestId(`tenant-name-${tenantName}`)).toHaveCount(0, { timeout: 15000 });
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
    await expect(page.locator('.pt-4 pre').nth(1)).toBeVisible({ timeout: 10000 });
    
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
    
    // Check for "Budget Utilization" chart
    await expect(page.getByText('Budget Utilization')).toBeVisible();
  });

  test('Sidebar: should persist tenant selection', async ({ page }) => {
    // 1. Get available tenants
    const selector = page.locator('select');
    await expect(selector).toBeVisible();

    const options = await selector.locator('option').all();
    if (options.length > 1) {
      const targetId = await options[1].getAttribute('value');
      
      // 2. Select the second tenant
      await selector.selectOption(targetId!);
      // Give it a moment to persist to localStorage
      await page.waitForTimeout(500);
      
      // 3. Verify it persists after navigation
      await page.goto('/settings');
      await page.waitForLoadState('networkidle');
      
      // Select might take a moment to populate from API
      await expect(page.locator('select')).toHaveValue(targetId!, { timeout: 10000 });
    }
  });

});
