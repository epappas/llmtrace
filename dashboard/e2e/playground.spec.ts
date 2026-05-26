import { test, expect } from "@playwright/test";

// ---------------------------------------------------------------------------
// Smoke + behaviour test for /playground (issue #284).
//
// Why we mock `/api/proxy/v1/chat/completions` via Playwright's `page.route`:
//
//   The CI proxy stack does NOT have an upstream provider API key (OpenAI,
//   Anthropic, etc.) configured — a real round-trip would fail at the
//   upstream provider, not in any LLMTrace code we control. That makes a
//   live POST useless as a regression signal here. To keep this spec
//   deterministic and runnable in CI, we intercept ONLY the upstream call
//   and return a canned OpenAI-shaped response. Every other request hits
//   the real proxy. The actual live round-trip is gated to a manual
//   maintainer-run smoke against a deployed environment with provider
//   credentials.
//
// What we assert end-to-end against the CI stack:
//   1. Authenticated GET /playground -> 200 + "Playground" heading.
//   2. The sidebar exposes a "Playground" link to /playground.
//   3. The page renders the model dropdown, temperature slider, system
//      prompt textarea, message input, and send button.
//   4. With the upstream mocked, sending a message appends an assistant
//      message containing the canned content to the transcript.
// ---------------------------------------------------------------------------

const PROXY_BASE = process.env.LLMTRACE_PROXY_URL ?? "http://127.0.0.1:8081";

test.describe("Playground page (issue #284)", () => {
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
    // Mirror api-docs.spec.ts: fetch the seeded username, then login.
    const identityRes = await request.get("/api/auth/identity");
    const identity = (await identityRes.json()) as { username: string };
    const loginRes = await request.post("/api/auth/login", {
      data: { username: identity.username, admin_key: "test-key-for-ci-stack" },
      headers: { "Content-Type": "application/json" },
    });
    expect(loginRes.status(), `login failed: ${await loginRes.text()}`).toBe(200);
  });

  test("/playground renders 200 with the Playground heading", async ({ page }) => {
    const response = await page.goto("/playground");
    expect(response?.status()).toBe(200);
    await expect(
      page.getByRole("heading", { name: "Playground", exact: true }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("sidebar exposes Playground link", async ({ page }) => {
    await page.goto("/playground");
    const link = page.locator("aside").getByRole("link", { name: "Playground" });
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute("href", "/playground");
  });

  test("renders model, temperature, system prompt, input, and send button", async ({ page }) => {
    await page.goto("/playground");
    await expect(page.getByTestId("playground-model")).toBeVisible();
    await expect(page.getByTestId("playground-temperature")).toBeVisible();
    await expect(page.getByTestId("playground-system-prompt")).toBeVisible();
    await expect(page.getByTestId("playground-input")).toBeVisible();
    await expect(page.getByTestId("playground-send")).toBeVisible();
  });

  test("sending a message renders the assistant reply (upstream mocked)", async ({ page }) => {
    // Intercept the dashboard proxy route ONLY. Every other request reaches
    // the live stack untouched. See header comment for rationale.
    await page.route("**/api/proxy/v1/chat/completions", async (route) => {
      const fakeOpenAi = {
        id: "chatcmpl-test-fixture",
        object: "chat.completion",
        created: 1_700_000_000,
        model: "gpt-4o-mini",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "Pong from the mocked upstream." },
            finish_reason: "stop",
          },
        ],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "x-llmtrace-trace-id": "trace-fixture-1" },
        body: JSON.stringify(fakeOpenAi),
      });
    });

    await page.goto("/playground");
    await page.getByTestId("playground-input").fill("ping");
    await page.getByTestId("playground-send").click();

    const assistant = page.getByTestId("playground-msg-assistant");
    await expect(assistant).toBeVisible({ timeout: 10_000 });
    await expect(assistant).toContainText("Pong from the mocked upstream.");
  });
});
