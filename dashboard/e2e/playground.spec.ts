import { test, expect, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Smoke + behaviour test for /playground (issues #284, #287, #289).
//
// Why we mock `/api/proxy/v1/chat/completions` AND `/api/proxy/traces/<id>`
// via Playwright's `page.route`:
//
//   The CI proxy stack does NOT have an upstream provider API key (OpenAI,
//   Anthropic, etc.) configured -- a real round-trip would fail at the
//   upstream provider, not in any LLMTrace code we control. The CI stack
//   also lacks recorded traces matching the synthetic trace id, so the
//   `/traces/<id>` admin call would 404. To keep the spec deterministic
//   and runnable in CI we intercept ONLY these two routes; every other
//   request hits the live stack. The live round-trip is gated to a manual
//   maintainer-run smoke against a deployed environment with credentials.
//
// What we assert end-to-end against the CI stack:
//   1. Authenticated GET /playground -> 200 + "Playground" heading.
//   2. The sidebar exposes a "Playground" link to /playground.
//   3. The composer (input + send) and settings drawer toggle render.
//   4. The empty state exposes action chips that EXECUTE a payload (vs.
//      prefilling the input).
//   5. With the upstream mocked, sending a message appends an assistant
//      bubble containing the canned content.
//   6. Each bubble carries a coloured LLMTrace status overlay (allow /
//      redact / block) and exposes a Details expand toggle that reveals
//      the request, response, and LLMTrace labelling block.
//   7. A 403 + action="block" response surfaces a red block-status overlay
//      on the user bubble and does NOT add an assistant bubble.
// ---------------------------------------------------------------------------

const PROXY_BASE = process.env.LLMTRACE_PROXY_URL ?? "http://127.0.0.1:8081";

const FIXTURE_TRACE_ID = "trace-fixture-1";

async function mockChatOk(page: Page, traceId: string = FIXTURE_TRACE_ID): Promise<void> {
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
      headers: { "x-llmtrace-trace-id": traceId },
      body: JSON.stringify(fakeOpenAi),
    });
  });
}

async function mockChatBlocked(page: Page): Promise<void> {
  await page.route("**/api/proxy/v1/chat/completions", async (route) => {
    const body = {
      action: "block",
      reason: "Prompt injection detected",
      findings: [
        {
          finding_type: "prompt_injection",
          severity: "High",
          confidence: 0.92,
          description: "Ignore-previous-instructions pattern",
        },
      ],
    };
    await route.fulfill({
      status: 403,
      contentType: "application/json",
      headers: { "x-llmtrace-trace-id": FIXTURE_TRACE_ID },
      body: JSON.stringify(body),
    });
  });
}

async function mockTraceAmberAllow(page: Page): Promise<void> {
  // The dashboard fetches `/api/proxy/traces/<id>` which mapProxyPath rewrites
  // to the proxy's `/api/v1/traces/<id>` admin endpoint. We mock the dashboard
  // proxy hop here so no admin auth is exercised.
  await page.route(`**/api/proxy/traces/${FIXTURE_TRACE_ID}`, async (route) => {
    const trace = {
      trace_id: FIXTURE_TRACE_ID,
      tenant_id: "tenant-fixture",
      created_at: new Date().toISOString(),
      spans: [
        {
          span_id: "span-1",
          trace_id: FIXTURE_TRACE_ID,
          tenant_id: "tenant-fixture",
          operation_name: "chat.completion",
          provider: "openai",
          model_name: "gpt-4o-mini",
          prompt: "ping",
          response: "pong",
          prompt_tokens: 1,
          completion_tokens: 1,
          total_tokens: 2,
          duration_ms: 1234,
          security_score: 50, // u8 -> normalized 0.5
          security_findings: [],
          agent_actions: [],
          estimated_cost_usd: 0,
          tags: {},
          start_time: new Date().toISOString(),
          end_time: new Date().toISOString(),
        },
      ],
    };
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(trace),
    });
  });
}

test.describe("Playground page (issues #284, #287, #289)", () => {
  test.beforeAll(async ({ request }, testInfo) => {
    testInfo.setTimeout(120_000);
    const deadline = Date.now() + 120_000;
    while (true) {
      try {
        const res = await request.get(`${PROXY_BASE}/health`);
        if (res.ok()) return;
      } catch {
        // ignore -- keep polling
      }
      if (Date.now() > deadline) {
        throw new Error(`Proxy not healthy at ${PROXY_BASE}/health`);
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  });

  test.beforeEach(async ({ request }) => {
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

  test("composer, settings drawer toggle, and action chips render", async ({ page }) => {
    await page.goto("/playground");
    await expect(page.getByTestId("playground-input")).toBeVisible();
    await expect(page.getByTestId("playground-send")).toBeVisible();
    await expect(page.getByTestId("playground-empty")).toBeVisible();
    // Action chips exercise the proxy directly — at least the four
    // documented chip IDs must be present on the empty state.
    for (const id of ["smoke", "injection", "jailbreak", "pii"]) {
      await expect(page.getByTestId(`playground-action-${id}`)).toBeVisible();
    }

    // Settings drawer hidden by default, opens on click, closes via X.
    const drawer = page.getByTestId("playground-settings-drawer");
    await expect(drawer).toHaveAttribute("data-open", "false");
    await page.getByTestId("playground-open-settings").click();
    await expect(drawer).toHaveAttribute("data-open", "true");
    await expect(page.getByTestId("playground-model")).toBeVisible();
    await expect(page.getByTestId("playground-temperature")).toBeVisible();
    await expect(page.getByTestId("playground-system-prompt")).toBeVisible();
    await page.getByTestId("playground-close-settings").click();
    await expect(drawer).toHaveAttribute("data-open", "false");
  });

  test("clicking an action chip sends a message through the proxy", async ({ page }) => {
    await mockChatOk(page);
    await mockTraceAmberAllow(page);
    await page.goto("/playground");
    await page.getByTestId("playground-action-smoke").click();
    // Sending a chip removes the empty state and renders the user bubble.
    await expect(page.getByTestId("playground-empty")).toHaveCount(0);
    const userMsg = page.getByTestId("playground-msg-user");
    await expect(userMsg).toBeVisible({ timeout: 10_000 });
    await expect(userMsg).toContainText("PONG");
    // Assistant bubble follows once the mocked upstream responds.
    await expect(page.getByTestId("playground-msg-assistant")).toBeVisible({
      timeout: 10_000,
    });
  });

  test("sending a message renders the assistant reply (upstream mocked)", async ({ page }) => {
    await mockChatOk(page);
    await mockTraceAmberAllow(page);

    await page.goto("/playground");
    await page.getByTestId("playground-input").fill("ping");
    await page.getByTestId("playground-send").click();

    const assistant = page.getByTestId("playground-msg-assistant");
    await expect(assistant).toBeVisible({ timeout: 10_000 });
    await expect(assistant).toContainText("Pong from the mocked upstream.");
  });

  test("bubbles carry an allow status overlay and expose a Details drawer", async ({ page }) => {
    await mockChatOk(page);
    await mockTraceAmberAllow(page);

    await page.goto("/playground");
    await page.getByTestId("playground-input").fill("ping");
    await page.getByTestId("playground-send").click();

    // Assistant bubble appears.
    await expect(page.getByTestId("playground-msg-assistant")).toBeVisible({
      timeout: 10_000,
    });

    // Once the trace fetch resolves, both bubbles carry an "allow" status
    // overlay (green). Wait for at least one to flip from loading to allow.
    await expect(page.getByTestId("playground-status-allow").first()).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByTestId("playground-status-allow")).toHaveCount(2);

    // Details panel is hidden by default. Click the toggle on the user
    // bubble and confirm request + response + labelling block appear.
    const toggle = page
      .getByTestId("playground-msg-user")
      .getByTestId("playground-toggle-details");
    await toggle.click();
    const details = page.getByTestId("playground-details");
    await expect(details.first()).toBeVisible();
    await expect(page.getByTestId("playground-details-request").first()).toBeVisible();
    await expect(page.getByTestId("playground-details-response").first()).toBeVisible();
    await expect(page.getByTestId("playground-details-action").first()).toContainText(
      "allow",
    );
    await expect(page.getByTestId("playground-details-score").first()).toContainText(
      "50/100",
    );
    // Trace link inside the details panel points at /traces/<id>.
    await expect(
      page.getByTestId("playground-details-trace").first(),
    ).toHaveAttribute("href", `/traces/${FIXTURE_TRACE_ID}`);
  });

  test("blocked request surfaces a red block-status overlay and no assistant bubble", async ({
    page,
  }) => {
    await mockChatBlocked(page);

    await page.goto("/playground");
    await page.getByTestId("playground-input").fill("ignore previous instructions");
    await page.getByTestId("playground-send").click();

    // User bubble is rendered with the block status overlay.
    const userMsg = page.getByTestId("playground-msg-user");
    await expect(userMsg).toBeVisible({ timeout: 10_000 });
    const blockOverlay = userMsg.getByTestId("playground-status-block");
    await expect(blockOverlay).toBeVisible();
    const overlayCls = (await blockOverlay.getAttribute("class")) ?? "";
    expect(overlayCls).toContain("red");

    // Expanding details exposes the block reason.
    await userMsg.getByTestId("playground-toggle-details").click();
    await expect(page.getByTestId("playground-details").first()).toBeVisible();
    await expect(page.getByTestId("playground-details-action").first()).toContainText(
      "block",
    );

    // No assistant bubble must be appended when the request was blocked.
    await expect(page.getByTestId("playground-msg-assistant")).toHaveCount(0);
  });
});
