import { expect, test, type Page } from "@playwright/test";

function installHealthRoute(
  page: Page,
  handler: (callCount: number) => {
    status: number;
    body: Record<string, unknown>;
  },
) {
  let healthCalls = 0;
  void page.route("**/health", async (route) => {
    healthCalls += 1;
    const response = handler(healthCalls);
    await route.fulfill({
      status: response.status,
      contentType: "application/json",
      body: JSON.stringify(response.body),
    });
  });
}

test.describe("Proxy lifecycle UX", () => {
  test.describe.configure({ mode: "serial" });

  test("shows startup overlay and auto-transitions to ready", async ({ page }) => {
    installHealthRoute(page, (healthCalls) => {
      if (healthCalls <= 6) {
        return {
          status: 200,
          body: {
            status: "starting",
            starting: true,
            ml: { status: "initializing", loaded_models: 1, total_models: 2 },
          },
        };
      }

      return {
        status: 200,
        body: { status: "healthy", starting: false },
      };
    });

    await page.goto("/");
    await expect(page.getByTestId("proxy-loading-overlay")).toBeAttached();
    await expect(page.getByTestId("proxy-loading-overlay")).toBeHidden({
      timeout: 20_000,
    });
  });

  test("shows a global reconnect banner when proxy restarts", async ({ page }) => {
    installHealthRoute(page, (healthCalls) => {
      if (healthCalls === 1) {
        return {
          status: 200,
          body: { status: "healthy", starting: false },
        };
      }
      return {
        status: 200,
        body: {
          status: "starting",
          starting: true,
          ml: { status: "initializing", progress_pct: 10 },
        },
      };
    });

    await page.goto("/");
    await expect(page.getByTestId("proxy-reconnect-banner")).toBeVisible({
      timeout: 10_000,
    });
    await expect(
      page.getByText("Proxy is restarting. Security engines are reloading..."),
    ).toBeVisible();
  });

  test("uses exponential backoff while retrying failed health checks", async ({
    page,
  }) => {
    installHealthRoute(page, (healthCalls) => {
      if (healthCalls === 1) {
        return {
          status: 200,
          body: { status: "healthy", starting: false },
        };
      }

      return {
        status: 503,
        body: { status: "down" },
      };
    });

    await page.goto("/");
    await expect(page.getByTestId("proxy-reconnect-banner")).toBeVisible({
      timeout: 10_000,
    });

    const seenBackoffValues = new Set<number>();
    await expect
      .poll(
        async () => {
          const text = await page
            .getByTestId("proxy-retry-delay-ms")
            .textContent();
          const value = Number(text?.match(/\d+/)?.[0] ?? "0");
          if (value > 0) {
            seenBackoffValues.add(value);
          }
          return seenBackoffValues.size;
        },
        { timeout: 15_000 },
      )
      .toBeGreaterThanOrEqual(2);

    const values = Array.from(seenBackoffValues).sort((a, b) => a - b);
    expect(values[0]).toBeGreaterThanOrEqual(500);
    expect(values[values.length - 1]).toBeGreaterThan(values[0]);
    const attemptText = await page
      .getByTestId("proxy-retry-attempt")
      .textContent({ timeout: 15_000 });
    const attemptValue = Number(attemptText?.match(/\d+/)?.[0] ?? "0");
    expect(attemptValue).toBeGreaterThanOrEqual(2);
  });

  test("clears reconnect state and returns to ready when health recovers", async ({
    page,
  }) => {
    installHealthRoute(page, (healthCalls) => {
      if (healthCalls === 1) {
        return {
          status: 200,
          body: { status: "healthy", starting: false },
        };
      }

      if (healthCalls === 2) {
        return {
          status: 503,
          body: { status: "down" },
        };
      }

      if (healthCalls <= 4) {
        return {
          status: 503,
          body: { status: "down" },
        };
      }

      return {
        status: 200,
        body: { status: "healthy", starting: false },
      };
    });

    await page.goto("/");
    await expect(page.getByTestId("proxy-reconnect-banner")).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByTestId("proxy-reconnect-banner")).toBeHidden({
      timeout: 15_000,
    });
  });
});
