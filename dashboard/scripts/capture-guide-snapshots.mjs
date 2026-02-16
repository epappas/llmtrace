#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { chromium } from "@playwright/test";

const baseUrl = process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:3000";
const outDir = path.resolve(process.cwd(), "public", "guide");

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function capture(page, route, filename, setup) {
  await page.goto(`${baseUrl}${route}`, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await page.waitForTimeout(1200);
  if (setup) {
    await setup(page);
  }
  await page.screenshot({
    path: path.join(outDir, filename),
    fullPage: true,
  });
  console.log(`captured: ${filename}`);
}

async function main() {
  await ensureDir(outDir);
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  await capture(page, "/", "overview.png");
  await capture(page, "/traces", "traces.png");
  await capture(
    page,
    "/traces",
    "trace-details.png",
    async (p) => {
      const rows = p.locator("tbody tr");
      const count = await rows.count();
      if (count > 0) {
        await rows.first().click();
        await p.waitForTimeout(1200);
      }
    },
  );
  await capture(page, "/security", "security.png");
  await capture(page, "/costs", "costs.png");
  await capture(page, "/tenants", "tenants.png");
  await capture(page, "/compliance", "compliance.png");
  await capture(page, "/settings", "settings.png");

  await browser.close();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

