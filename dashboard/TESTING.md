# LLMTrace Dashboard - End-to-End Testing Guide

This directory contains E2E tests written in [Playwright](https://playwright.dev/) to verify the functionality of the LLMTrace Dashboard.

## Prerequisites

-   Docker and Docker Compose installed and running.
-   The LLMTrace stack must be up and running (`docker compose up -d`).
-   Node.js (v18+) and npm (optional, if running locally).

## Test Suite Coverage

The tests in `e2e/dashboard.spec.ts` cover the following critical user flows:

1.  **Overview Page:** Verifies global stats, trace counts, and activity chart rendering.
2.  **Tenant Management:**
    *   Creating a new tenant.
    *   Generating an API token (verifying the UI displays it).
    *   Deleting a tenant.
3.  **Traces:**
    *   Filtering by Trace ID and Model.
    *   Verifying data in the table.
4.  **Trace Details:**
    *   Clicking a trace to view details.
    *   Verifying the "Prompt" and "Response" tabs display content correctly.
5.  **Security & Costs:** Verifying these pages load and display their respective charts/cards.
6.  **Persistence:** Ensuring the Sidebar's tenant selector remembers your choice after page reloads.

## Running Tests

### Option 1: Using Docker (Recommended)

This method requires no local Node.js installation and ensures a consistent environment with all necessary browsers installed.

Make sure your dashboard is running on `http://localhost:3000`.

Run the following command from the root of the repo (where `llmtrace/` is):

```bash
docker run --rm \
  --network host \
  -v $(pwd)/llmtrace/dashboard:/work \
  -w /work \
  mcr.microsoft.com/playwright:v1.58.2-jammy \
  /bin/bash -c "npm ci && npx playwright test"
```

*Note: We use `--network host` so the test container can access `localhost:3000`.*

### Option 2: Running Locally

If you have Node.js installed:

1.  Navigate to the dashboard directory:
    ```bash
    cd llmtrace/dashboard
    ```

2.  Install dependencies:
    ```bash
    npm install
    ```

3.  Install Playwright browsers:
    ```bash
    npx playwright install --with-deps
    ```

4.  Run the tests:
    ```bash
    npm run test:e2e
    ```

## Viewing Results

-   **Console Output:** The test results (Pass/Fail) will be printed to the console.
-   **HTML Report:** If tests fail, an HTML report is generated in `playwright-report/`. You can view it by running `npx playwright show-report`.
